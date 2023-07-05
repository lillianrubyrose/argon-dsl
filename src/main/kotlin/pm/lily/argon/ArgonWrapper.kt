package pm.lily.argon

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom

@Suppress("MemberVisibilityCanBePrivate")
object ArgonWrapper {
    private val rng = SecureRandom()

    const val HASH_LENGTH = 32
    const val SALT_LENGTH = HASH_LENGTH / 2

    const val TYPE = Argon2Parameters.ARGON2_id

    // 64MiB
    const val MEMORY_LIMIT = 1024 * 64
    const val ITERATIONS = 3
    const val PARALLELISM = 2

    val defaultParams: Argon2Parameters.Builder = Argon2Parameters.Builder(TYPE)
        .withMemoryAsKB(MEMORY_LIMIT)
        .withIterations(ITERATIONS)
        .withParallelism(PARALLELISM)

    private fun genSalt(length: Int = SALT_LENGTH) = ByteArray(length).also {
        rng.nextBytes(it)
    }

    /**
     * Hashes the [plaintext] based off of the params provided.
     *
     * @return A pair of the hash bytes and the parameters used
     */
    fun hash(
        plaintext: String,
        hashLength: Int = HASH_LENGTH,
        inParams: Argon2Parameters.Builder = defaultParams
    ): Pair<ByteArray, Argon2Parameters> {
        val result = ByteArray(hashLength)

        val params = inParams.withSalt(genSalt()).build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        gen.generateBytes(plaintext.toCharArray(), result)

        return Pair(result, params)
    }

    /**
     * Verifies that the [plaintext] matches the hash provided.
     *
     * @return True if the [plaintext] matches
     */
    fun verify(plaintext: String, hashAndParams: Pair<ByteArray, Argon2Parameters>): Boolean {
        val (hash, params) = hashAndParams

        val gen = Argon2BytesGenerator()
        gen.init(params)

        val result = ByteArray(hash.size)
        gen.generateBytes(plaintext.toCharArray(), result)

        return hash.contentEquals(result)
    }
}