package comm.example.jni.cryptionproject

import java.lang.StringBuilder
import java.security.MessageDigest

/**
 * 消息摘要
 */
object MessageDigetUtil {
    fun md5(input:String): String {
        val digest = MessageDigest.getInstance("MD5")
        val byteArray = digest.digest(input.toByteArray())
        return toHex(byteArray)
    }

    fun sha1(input:String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val result = digest.digest(input.toByteArray())
        return toHex(result)
    }

    fun sha256(input:String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val result = digest.digest(input.toByteArray())
        return toHex(result)
    }

    fun toHex(byteArray: ByteArray): String {
        //高阶函数
        val result = with(StringBuilder()){
            byteArray.forEach {
                val value = it
                val hex = value.toInt() and (0xFF)
                val hexStr = Integer.toHexString(hex)
//                println(hexStr)
                if (hexStr.length == 1){
                    //this可省略
                    append("0").append(hexStr)
                }else{
                    append(hexStr)
                }
            }
            this.toString()
        }
        return result
    }
}

fun main(args: Array<String>) {
    val input = "消息摘要MD5"

    val md5 = MessageDigetUtil.md5(input)

    println("MD5加密$md5")
    println(md5.toByteArray().size)

    val sha1 = MessageDigetUtil.sha1(input)
    println("SHA1加密$sha1")
    println(sha1.toByteArray().size)

    val sha256 = MessageDigetUtil.sha256(input)
    println("SHA256加密$sha256")
    println(sha256.toByteArray().size)
}