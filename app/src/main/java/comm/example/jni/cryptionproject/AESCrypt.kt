package comm.example.jni.cryptionproject

import com.itheima.crypt.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun main(args: Array<String>) {
    val password = "1234567812345678"
    val input = "这是我的加密AES信息"

    val encrypt = AESCrypt.encrypt(password, input)
    println("AES加密:$encrypt")
    val decrypt = AESCrypt.decrypt(password, encrypt)
    println("AES解密:$decrypt")
}

object AESCrypt{
    //算法/工作模式/填充模式
//    val transformation = "AES/ECB/PKCS5Padding"
    val transformation = "AES/CBC/PKCS5Padding"
    //算法
    val algorithm = "AES"
    /**
     * 加密
     */
    fun encrypt(password:String,input:String): String {
        //1.创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        //通过秘钥工厂生产秘钥
        val keySpec:SecretKeySpec = SecretKeySpec(password.toByteArray(),algorithm)
//        cipher.init(Cipher.ENCRYPT_MODE,keySpec)
        //CBC模式需要添加额外参数
        val iv = IvParameterSpec(password.toByteArray())
        cipher.init(Cipher.ENCRYPT_MODE,keySpec,iv)
        //3.加密/解密
        val encrypt = cipher.doFinal(input.toByteArray())
        val result = Base64.encode(encrypt)
        return result
    }

    /**
     * 解密
     */
    fun decrypt(password:String,input:String): String {
        //1.创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        //通过秘钥工厂生产秘钥
        val keySpec:SecretKeySpec = SecretKeySpec(password.toByteArray(),algorithm)
//        cipher.init(Cipher.DECRYPT_MODE,keySpec)
        //CBC模式需要添加额外参数
        val iv = IvParameterSpec(password.toByteArray())
        cipher.init(Cipher.DECRYPT_MODE,keySpec,iv)
        //3.加密/解密
        val decrypt = cipher.doFinal(Base64.decode(input))
        val result = String(decrypt)
        return result
    }
}