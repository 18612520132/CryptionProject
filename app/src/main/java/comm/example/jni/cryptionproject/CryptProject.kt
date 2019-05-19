package comm.example.jni.cryptionproject

import com.itheima.crypt.HttpUtil
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.FileReader
import java.io.FileWriter

fun main(args: Array<String>) {
    val key = "1234567812345678"//AES秘钥

    //获取联系人
    val json = HttpUtil.request("https://www.wanandroid.com/project/tree/json")
    println("服务器:$json")
    //QQ将联系人缓存到本地：加密
//    val bw = BufferedWriter(FileWriter("UserInfo.db"))
//    val encrypt = AESCrypt.encrypt(key,json)
//    bw.write(encrypt)
//    bw.close()


    //显示：解密
    val br = BufferedReader(FileReader("UserInfo.db"))
    val readLine = br.readLine()
    println("获取本地加密内容：$readLine")
    val decrypt = AESCrypt.decrypt(key, readLine)
    println("对加密内容进行解密:$decrypt")

}