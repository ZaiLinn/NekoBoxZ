package io.nekohasekai.sagernet.database

import android.os.Parcel
import io.nekohasekai.sagernet.database.preference.KeyValuePair
import io.nekohasekai.sagernet.database.preference.PublicDatabase
import moe.matsuri.nb4a.utils.Util
import org.json.JSONObject
import io.nekohasekai.sagernet.utils.BoundedInput

/** Parse everything before writing; use one rollback-journal transaction across both files. */
object BackupRestore {
    data class Plan(
        val profiles: List<ProxyEntity>?, val groups: List<ProxyGroup>?,
        val rules: List<RuleEntity>?, val settings: List<KeyValuePair>?,
    )

    fun parse(content: JSONObject, profile: Boolean, rule: Boolean, setting: Boolean): Plan {
        require(content.getInt("version") == 1) { "Unsupported backup version" }
        fun <T> decode(name: String, creator: (Parcel) -> T): List<T> {
            val array = content.getJSONArray(name)
            require(array.length() <= BoundedInput.MAX_ENTRIES) { "Too many backup entries" }
            return (0 until array.length()).map { i ->
                val bytes = Util.b64Decode(array.getString(i))
                require(bytes.size <= 4 * 1024 * 1024) { "Backup entry too large" }
                val parcel = Parcel.obtain()
                try {
                    parcel.unmarshall(bytes, 0, bytes.size)
                    parcel.setDataPosition(0)
                    creator(parcel).also { require(parcel.dataAvail() == 0) { "Invalid backup entry" } }
                } finally { parcel.recycle() }
            }
        }
        val profiles = if (profile && content.has("profiles")) decode("profiles", ProxyEntity.CREATOR::createFromParcel) else null
        val groups = if (profiles != null) decode("groups", ProxyGroup.CREATOR::createFromParcel) else null
        val rules = if (rule && content.has("rules")) decode("rules", ParcelizeBridge::createRule) else null
        val settings = if (setting && content.has("settings")) decode("settings", KeyValuePair.CREATOR::createFromParcel) else null
        fun validIds(ids: List<Long>) = ids.all { it > 0 } && ids.distinct().size == ids.size
        require(profiles == null || validIds(profiles.map { it.id })) { "Invalid profile IDs" }
        require(groups == null || validIds(groups.map { it.id })) { "Invalid group IDs" }
        require(rules == null || validIds(rules.map { it.id })) { "Invalid rule IDs" }
        if (profiles != null) {
            val ids = groups!!.map { it.id }.toSet()
            require(profiles.all { it.groupId in ids }) { "Profile references a missing group" }
        }
        require(settings == null || settings.map { it.key }.distinct().size == settings.size) { "Duplicate setting keys" }
        settings?.forEach {
            require(it.key.isNotBlank() && it.valueType in 0..6) { "Invalid setting" }
            val expected = when (it.valueType) { 1 -> 1; 2, 3 -> 4; 4 -> 8; else -> null }
            require(expected == null || it.value.size == expected) { "Invalid setting value" }
            if (it.valueType == 6) {
                val buffer = java.nio.ByteBuffer.wrap(it.value)
                while (buffer.hasRemaining()) {
                    require(buffer.remaining() >= 4) { "Invalid string set" }
                    val length = buffer.int
                    require(length in 0..buffer.remaining()) { "Invalid string set length" }
                    buffer.position(buffer.position() + length)
                }
            }
        }
        return Plan(profiles, groups, rules, settings)
    }

    fun restore(plan: Plan, database: SagerDatabase = SagerDatabase.instance,
                settingsDatabase: PublicDatabase = PublicDatabase.instance) {
        val sql = database.openHelper.writableDatabase
        var attached = false
        try {
            if (plan.settings != null) {
                val settingsSql = settingsDatabase.openHelper.writableDatabase
                // SQLite multi-file crash atomicity requires on-disk rollback journals, not WAL.
                for (db in listOf(sql, settingsSql)) {
                    db.query("PRAGMA journal_mode").use {
                        check(it.moveToFirst() && it.getString(0).equals("truncate", true)) {
                            "Restore requires rollback journals"
                        }
                    }
                }
                sql.execSQL("ATTACH DATABASE ? AS restore_settings", arrayOf(settingsSql.path))
                attached = true
            }
            database.runInTransaction {
                plan.profiles?.let {
                    database.proxyDao().reset()
                    database.groupDao().reset()
                    database.groupDao().insert(plan.groups!!)
                    database.proxyDao().insert(it)
                }
                plan.rules?.let {
                    database.rulesDao().reset()
                    database.rulesDao().insert(it)
                }
                plan.settings?.let { settings ->
                    sql.execSQL("DELETE FROM restore_settings.KeyValuePair")
                    settings.forEach {
                        sql.execSQL("INSERT INTO restore_settings.KeyValuePair (`key`, valueType, value) VALUES (?, ?, ?)",
                            arrayOf(it.key, it.valueType, it.value))
                    }
                }
            }
        } finally {
            if (attached) sql.execSQL("DETACH DATABASE restore_settings")
        }
        // Caller immediately restarts both processes, invalidating all cached preferences.
    }
}
