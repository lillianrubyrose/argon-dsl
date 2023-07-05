@file:Suppress("unused")

package pm.lily.argon

import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Hashes and encodes [this] into a db-safe string meant for storage.

 * Default parameters are safe for almost every use-case and widely
 * regarded as good defaults for passwords.
 *
 * @return The encoded hash
 */
fun String.argonHash(
    hashLength: Int = ArgonWrapper.HASH_LENGTH,
    params: Argon2Parameters.Builder = ArgonWrapper.defaultParams
): String {
    val hashAndParams = ArgonWrapper.hash(this, hashLength, params)
    return ArgonEncoder.encode(hashAndParams)
}

/**
 * WARNING: Assumes [this] is an encoded string, it CAN and WILL
 * fail if it isn't, throwing an unchecked exception.
 *
 * Decodes and verifies that [plaintext] matches the hash of [this]
 *
 * @return True if [plaintext] matches the hash of [this]
 */
fun String.argonVerify(plaintext: String): Boolean {
    val decoded = ArgonEncoder.decode(this)
    return ArgonWrapper.verify(plaintext, decoded)
}