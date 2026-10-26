package io.nekohasekai.sagernet.database

import android.app.Application
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.test.core.app.ApplicationProvider
import io.nekohasekai.sagernet.database.preference.KeyValuePair
import io.nekohasekai.sagernet.database.preference.PublicDatabase
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import org.json.JSONObject
import org.junit.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [28])
class RestoreAndTrafficTest {
    private lateinit var db: SagerDatabase
    private lateinit var settings: PublicDatabase
    @Before fun setUp() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        app.deleteDatabase("restore-test"); app.deleteDatabase("settings-test")
        db = Room.databaseBuilder(app, SagerDatabase::class.java, "restore-test")
            .setJournalMode(RoomDatabase.JournalMode.TRUNCATE).allowMainThreadQueries().build()
        settings = Room.databaseBuilder(app, PublicDatabase::class.java, "settings-test")
            .setJournalMode(RoomDatabase.JournalMode.TRUNCATE).allowMainThreadQueries().build()
    }
    @After fun close() { db.close(); settings.close() }

    @Test fun trafficUpdatePreservesEditedMetadata() {
        val node = ProxyEntity(groupId = 1).apply {
            putBean(SOCKSBean().apply { initializeDefaultValues(); name = "original" })
        }
        node.id = db.proxyDao().addProxy(node)
        val edited = db.proxyDao().getById(node.id)!!
        edited.requireBean().name = "edited"
        edited.groupId = 7
        db.proxyDao().updateProxy(edited)
        db.proxyDao().addTraffic(node.id, 12, 34)
        val current = db.proxyDao().getById(node.id)!!
        Assert.assertEquals("edited", current.requireBean().name)
        Assert.assertEquals(7L, current.groupId)
        Assert.assertEquals(12L, current.rx)
        Assert.assertEquals(34L, current.tx)
    }

    @Test fun invalidLaterBackupSectionCannotDeleteExistingData() {
        db.rulesDao().insert(listOf(RuleEntity(id = 1, name = "keep")))
        try {
            BackupRestore.parse(JSONObject("{\"version\":1,\"profiles\":[]}"), true, false, false)
            Assert.fail("missing groups accepted")
        } catch (_: Exception) {}
        Assert.assertEquals("keep", db.rulesDao().allRules().single().name)
    }

    private fun setRollbackMode(mode: String) {
        for (database in listOf(db.openHelper.writableDatabase, settings.openHelper.writableDatabase)) {
            database.query("PRAGMA journal_mode=$mode").use {
                Assert.assertTrue(it.moveToFirst())
                Assert.assertEquals(mode, it.getString(0).lowercase(java.util.Locale.ROOT))
            }
        }
    }

    @Test fun restoreAcceptsAllOnDiskRollbackModes() {
        for (mode in listOf("delete", "truncate", "persist")) {
            setRollbackMode(mode)
            db.rulesDao().reset()
            db.rulesDao().insert(listOf(RuleEntity(id = 1, name = "old")))
            settings.keyValuePairDao().put(KeyValuePair("old").put("keep"))
            BackupRestore.restore(BackupRestore.Plan(null, null,
                listOf(RuleEntity(id = 2, name = mode)), listOf(KeyValuePair("new").put(mode))),
                db, settings)
            Assert.assertEquals(mode, db.rulesDao().allRules().single().name)
            Assert.assertNull(settings.keyValuePairDao()["old"])
            Assert.assertEquals(mode, settings.keyValuePairDao()["new"]!!.string)
        }
    }

    @Test fun secondDatabaseFailureRollsBackBothDatabases() {
        for (mode in listOf("delete", "truncate", "persist")) {
            setRollbackMode(mode)
            db.rulesDao().reset()
            db.rulesDao().insert(listOf(RuleEntity(id = 1, name = "keep")))
            settings.keyValuePairDao().put(KeyValuePair("old").put("keep"))
            // Fail in the second file after the first file has already been changed.
            val plan = BackupRestore.Plan(null, null, listOf(RuleEntity(id = 2, name = "new")),
                listOf(KeyValuePair("duplicate").put("a"), KeyValuePair("duplicate").put("b")))
            try { BackupRestore.restore(plan, db, settings); Assert.fail("expected constraint failure") }
            catch (_: android.database.sqlite.SQLiteException) {}
            Assert.assertEquals(mode, "keep", db.rulesDao().allRules().single().name)
            Assert.assertEquals(mode, "keep", settings.keyValuePairDao()["old"]!!.string)
            Assert.assertNull(settings.keyValuePairDao()["duplicate"])
        }
    }
}
