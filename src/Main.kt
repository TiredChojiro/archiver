import java.awt.image.BufferedImage
import java.io.*
import java.security.MessageDigest
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import javax.imageio.ImageIO

fun compress(input: ByteArray): ByteArray {
    val deflater = Deflater()
    deflater.setInput(input)
    deflater.finish()

    val outputStream = ByteArrayOutputStream(input.size)
    val buffer = ByteArray(1024)
    while (!deflater.finished()) {
        val count = deflater.deflate(buffer)
        outputStream.write(buffer, 0, count)
    }
    outputStream.close()
    return outputStream.toByteArray()
}

fun decompress(input: ByteArray): ByteArray {
    val inflater = InflaterInputStream(ByteArrayInputStream(input))
    val outputStream = ByteArrayOutputStream()
    val buffer = ByteArray(1024)
    var count: Int
    while (inflater.read(buffer).also { count = it } != -1) {
        outputStream.write(buffer, 0, count)
    }
    outputStream.close()
    return outputStream.toByteArray()
}

fun encrypt(input: ByteArray, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES")
    val secretKeySpec = SecretKeySpec(key, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
    return cipher.doFinal(input)
}

fun decrypt(input: ByteArray, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES")
    val secretKeySpec = SecretKeySpec(key, "AES")
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)
    return cipher.doFinal(input)
}

fun calculateHash(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}

fun hideDataInImage(data: ByteArray, imagePath: String, key: ByteArray, outputPath: String) {
    try {

        val compressedData = compress(data)
        val encryptedData = encrypt(compressedData, key)

        val originalHash = calculateHash(data)

        val image = ImageIO.read(File(imagePath))
        val width = image.width
        val height = image.height

        var dataIndex = 0
        for (y in 0 until height) {
            for (x in 0 until width) {
                if (dataIndex < encryptedData.size) {
                    val pixel = image.getRGB(x, y)
                    val newPixel = (pixel and 0xFFFFFF00.toInt()) or (encryptedData[dataIndex].toInt() and 0xFF)
                    image.setRGB(x, y, newPixel)
                    dataIndex++
                }
            }
        }

        val hashIndex = encryptedData.size
        for (i in 0 until originalHash.size) {
            val pixel = image.getRGB(i, height - 1)
            val newPixel = (pixel and 0xFFFFFF00.toInt()) or (originalHash[i].toInt() and 0xFF)
            image.setRGB(i, height - 1, newPixel)
        }

        ImageIO.write(image, "png", File(outputPath))
        println("Данные успешно спрятаны в изображении.")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

fun extractDataFromImage(imagePath: String, key: ByteArray, outputPath: String) {
    try {

        val image = ImageIO.read(File(imagePath))
        val width = image.width
        val height = image.height

        val outputStream = ByteArrayOutputStream()
        for (y in 0 until height - 1) {
            for (x in 0 until width) {
                val pixel = image.getRGB(x, y)
                val encryptedByte = pixel and 0xFF
                outputStream.write(encryptedByte)
            }
        }
        outputStream.close()
        val encryptedData = outputStream.toByteArray()

        val originalHash = ByteArray(32)
        for (i in 0 until originalHash.size) {
            val pixel = image.getRGB(i, height - 1)
            originalHash[i] = (pixel and 0xFF).toByte()
        }

        val decryptedData = decrypt(encryptedData, key)

        val decompressedData = decompress(decryptedData)

        val recalculatedHash = calculateHash(decompressedData)
        if (!recalculatedHash.contentEquals(originalHash)) {
            println("Ошибка: Хэш-сумма данных не совпадает. Данные повреждены.")
            return
        }

        val outputFile = File(outputPath)
        val output = FileOutputStream(outputFile)
        output.write(decompressedData)
        output.close()
        println("Данные успешно извлечены из изображения.")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

fun main() {
    val key = "This is good!".toByteArray()

    val inputFilePath = "file_one.txt"
    val imagePath = "it_image.png"
    val outputImagePath = "image_data.png"
    val extractedFilePath = "extra_file.txt"

    hideDataInImage(File(inputFilePath).readBytes(), imagePath, key, outputImagePath)

    extractDataFromImage(outputImagePath, key, extractedFilePath)
}
