package comm.example.jni.cryptionproject

import com.itheima.crypt.Base64
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

fun main(args: Array<String>) {
    val input = "这是我的加密DES信息"
    val password = "12345678"  //DES秘钥长度为  8 位

    val encrypt = DESCrypt.encrypt(input, password)
    println("DES加密:$encrypt")

    val decrypt = DESCrypt.decrypt(encrypt, password)
    println("DES解密:"+String(decrypt))
}

object DESCrypt{
    //算法/工作模式/填充模式
//    val transformation = "DES/ECB/PKCS5Padding"
    val transformation = "DES/CBC/PKCS5Padding"
    //算法
    val algorithm = "DES"
    /**
     *   DES 加密
     */
    fun encrypt(input:String,password:String): String {
        //1.创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        val skf = SecretKeyFactory.getInstance(algorithm)
        val keySpec = DESKeySpec(password.toByteArray())
        val key:Key = skf.generateSecret(keySpec)
        /**
         *  ENCRYPT_MODE  加密
         */
//        cipher.init(Cipher.ENCRYPT_MODE,key)
        //CBC模式需要添加额外参数
        val iv = IvParameterSpec(password.toByteArray())
        cipher.init(Cipher.ENCRYPT_MODE,key,iv)

        //3.加密/解密
        val encrypt = cipher.doFinal(input.toByteArray())
        return Base64.encode(encrypt)
    }

    /**
     *  DES 解密
     */
    fun decrypt(input:String,password:String): ByteArray {
        //1.创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        val skf = SecretKeyFactory.getInstance(algorithm)
        val keySpec = DESKeySpec(password.toByteArray())
        val key:Key? = skf.generateSecret(keySpec)
        /**
         *  DECRYPT_MODE  解密
         */
//        cipher.init(Cipher.DECRYPT_MODE,key)
        //CBC模式需要添加额外参数
        val iv = IvParameterSpec(password.toByteArray())
        cipher.init(Cipher.DECRYPT_MODE,key,iv)
        //3.加密/解密
//        val encrypt = cipher.doFinal(input.toByteArray())
        //base64
        val encrypt = cipher.doFinal(Base64.decode(input))

        return encrypt
    }
}