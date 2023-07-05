package pm.lily.argon

import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.util.encoders.Base64
import java.lang.IllegalArgumentException

object ArgonEncoder {
    /**
     * Encodes the hash into a db-safe string, so you can easily
     * do things like password hash validation.
     *
     * @param hashAndParams You can get this from [ArgonWrapper.hash]
     *
     * @return The encoded hash
     */
    fun encode(hashAndParams: Pair<ByteArray, Argon2Parameters>): String {
        val (hash, params) = hashAndParams

        var result = params.type.toString()
        result += ",${params.version}"
        result += ",${params.lanes}"
        result += ",${params.memory}"
        result += ",${params.iterations}"
        result += ",${Base64.toBase64String(params.salt)}"
        result += ",${Base64.toBase64String(hash)}"

        return result
    }

    /**
     * Decodes a [ArgonEncoder.encode]'d hash into the raw bytes and
     * parameters used to create the hash.
     *
     * @return A pair of the hash bytes and Argon parameters
     */
    fun decode(encoded: String): Pair<ByteArray, Argon2Parameters> {
        val split = encoded.split(",")
        if (split.size != 7) {
            throw IllegalArgumentException("bad encoded hash")
        }

        val type = split[0].toInt()
        val version = split[1].toInt()
        val lanes = split[2].toInt()
        val memory = split[3].toInt()
        val iterations = split[4].toInt()
        val salt = Base64.decode(split[5])
        val hash = Base64.decode(split[6])

        val params = Argon2Parameters.Builder(type)
            .withVersion(version)
            .withParallelism(lanes)
            .withMemoryAsKB(memory)
            .withIterations(iterations)
            .withSalt(salt)
            .build()

        return Pair(hash, params)
    }
}