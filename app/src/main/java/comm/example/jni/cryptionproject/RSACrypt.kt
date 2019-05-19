package comm.example.jni.cryptionproject

import com.itheima.crypt.Base64
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * 非对称加密RSA加密和解密
 */
object RSACrypt {
    val transformation = "RSA"
    val publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC039jg7sotX4xr+LGdmTWs7TgRGTAiMAINpAX8B1r8qUbiyHpqp4ozlQhOI8ogMM+p1rcDWTvM+8Iwd9laClFUeVYaun+h4XUgIM5nQ1qmTVN3uf1lYZxzf2a8B0pHWxPYDwIyeHj2UEb3Cx5i5NG5cZ24depXP6jPKwyzTTJtEwIDAQAB"
    val privateKeyStr = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALTf2ODuyi1fjGv4sZ2ZNaztOBEZMCIwAg2kBfwHWvypRuLIemqnijOVCE4jyiAwz6nWtwNZO8z7wjB32VoKUVR5Vhq6f6HhdSAgzmdDWqZNU3e5/WVhnHN/ZrwHSkdbE9gPAjJ4ePZQRvcLHmLk0blxnbh16lc/qM8rDLNNMm0TAgMBAAECgYAKlYrAZtjH3O5/pvblzQBaFSuRvJKXfY2xNKbw/5EwdctjG+4l7ZXlvNPWlruONK0COEFPXdpk/Vp4sZqzbSUjHcirJp4NifP+RuJAiAYzqkVT7kPykC9+id4JPsyLmKRt7bLc30vCtdFCADlYW0/vHHxMo5bENQb1ssmWSA9QgQJBAP50eLzPGQRhzeQqcJEDEK1xNqj3bJ2sL5nKi4BpHoORoqjnJkxXOsiunkh2vOLW1Hv/rRvuSv4BPQ61qmJwnNMCQQC1+QA6WuEchcnM/kDof0HAIFJQ6iWdavoLFldSW8Jt5xoWjJ/BBEs2KGnAGFtEPzjGIM5pthqONbUbQLwKW8bBAkB8yYncroPKTly2pMmHlEU9ieQQgSbXPHYrqdU4KFU6mNV4l8OEdNLzUA934iNH66tRFFZE+Fv2rYzQBe+FT0zZAkBR9I8RuRRhkC/Oz0PUclved7AbGRlPyHpMvAcf5Iuwi8DIHxVkDNcC0Tivd0jDd+XN9cCBA676FV43o/QMhkEBAkAVQiJlcrVNJHfG3/94VV3vs8iCwcFiMn14Rij7YqhkpdaY6rEM17Wttc/jowkkJ4bk7mmDJOHWyyPLYhJq4tiV"

    val ENCRYPT_MAX_SIZE = 117//加密每次最大加密的长度117字节
    val DECRYPT_MAX_SIZE = 128//解密每次最大加密的长度128字节

    fun getPrivateKey(): PrivateKey {

        //字符串转成秘钥对对象
        val kf = KeyFactory.getInstance("RSA")
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(privateKeyStr)))
        return  privateKey
    }

    fun getPublicKey(): PublicKey {

        //字符串转成秘钥对对象
        val kf = KeyFactory.getInstance("RSA")
        val publicKey = kf.generatePublic(X509EncodedKeySpec(Base64.decode(publicKeyStr)))
        return  publicKey
    }

    /**********************私钥加密  公钥解密**************************/
    /**
     * 私钥加密
     */
    fun entryptByPrivateKey(input:String,privateKey:PrivateKey): String {

        val byteArray = input.toByteArray()

        //创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //初始化
        cipher.init(Cipher.ENCRYPT_MODE,privateKey)
        //加密：分段加密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp:ByteArray? = null
        var offset = 0 //当前偏移的位置
        val bos = ByteArrayOutputStream()

        while (byteArray.size- offset > 0){//没加密完
            //每次最大加载117字节
            if (byteArray.size - offset >= ENCRYPT_MAX_SIZE){
                //剩余部分大于117
                //加密完整117
                temp = cipher.doFinal(byteArray,offset, ENCRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offset += ENCRYPT_MAX_SIZE
            }else{
                //加密到最后一块
                temp = cipher.doFinal(byteArray,offset, byteArray.size - offset)
                //重新计算偏移的位置
                offset = byteArray.size
            }
            //存储到临时缓冲器
            bos.write(temp)
        }
        bos.close()

        return Base64.encode(bos.toByteArray())
    }

    /**
     * 公钥解密
     */
    fun detryptByPublicKey(input:String,publicKey: PublicKey): String {

        val byteArray = Base64.decode(input)

        //创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //初始化
        cipher.init(Cipher.DECRYPT_MODE,publicKey)
        //加密：分段解密
        var temp:ByteArray? = null
        var offset = 0 //当前偏移的位置
        val bos = ByteArrayOutputStream()

        while (byteArray.size- offset > 0){//没加密完
            //每次最大加载128字节
            if (byteArray.size - offset >= DECRYPT_MAX_SIZE){
                temp = cipher.doFinal(byteArray,offset, DECRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offset += DECRYPT_MAX_SIZE
            }else{
                //加密到最后一块
                temp = cipher.doFinal(byteArray,offset, byteArray.size - offset)
                //重新计算偏移的位置
                offset = byteArray.size
            }
            //存储到临时缓冲器
            bos.write(temp)
        }
        bos.close()

        return String(bos.toByteArray())
    }
    /*******************公钥加密  私钥解密*************************/
    /**
     * 公钥加密
     */
    fun entryptByPublicKey(input:String,publicKey: PublicKey): String {

        val byteArray = input.toByteArray()

        //创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //初始化
        cipher.init(Cipher.ENCRYPT_MODE,publicKey)
        //加密：分段加密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp:ByteArray? = null
        var offset = 0 //当前偏移的位置
        val bos = ByteArrayOutputStream()

        while (byteArray.size- offset > 0){//没加密完
            //每次最大加载117字节
            if (byteArray.size - offset >= ENCRYPT_MAX_SIZE){
                //剩余部分大于117
                //加密完整117
                temp = cipher.doFinal(byteArray,offset, ENCRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offset += ENCRYPT_MAX_SIZE
            }else{
                //加密到最后一块
                temp = cipher.doFinal(byteArray,offset, byteArray.size - offset)
                //重新计算偏移的位置
                offset = byteArray.size
            }
            //存储到临时缓冲器
            bos.write(temp)
        }
        bos.close()

        return Base64.encode(bos.toByteArray())
    }
    /**
     * 私钥解密
     */
    fun detryptByPrivateKey(input:String,privateKey: PrivateKey): String {

        val byteArray = Base64.decode(input)

        //创建cipher对象
        val cipher = Cipher.getInstance(transformation)
        //初始化
        cipher.init(Cipher.DECRYPT_MODE,privateKey)
        //加密：分段解密
        var temp:ByteArray? = null
        var offset = 0 //当前偏移的位置
        val bos = ByteArrayOutputStream()

        while (byteArray.size- offset > 0){//没加密完
            //每次最大加载128字节
            if (byteArray.size - offset >= DECRYPT_MAX_SIZE){
                temp = cipher.doFinal(byteArray,offset, DECRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offset += DECRYPT_MAX_SIZE
            }else{
                //加密到最后一块
                temp = cipher.doFinal(byteArray,offset, byteArray.size - offset)
                //重新计算偏移的位置
                offset = byteArray.size
            }
            //存储到临时缓冲器
            bos.write(temp)
        }
        bos.close()

        return String(bos.toByteArray())
    }
}

fun main(args: Array<String>) {
     //生产秘钥对
//    val generator = KeyPairGenerator.getInstance("RSA")//秘钥对生成器
//    val keyPair = generator.genKeyPair()//生命秘钥对
//    val privateKey = keyPair.private //私钥
//    val publicKey = keyPair.public //公钥
//    println("/**********************公钥  私钥**************************/")
//    println("公钥publicKey==="+Base64.encode(publicKey.encoded))
//    println("私钥privateKey==="+Base64.encode(privateKey.encoded))
    /***************保存秘钥对****************/
    val publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCMcnaFTD5Xea8p9N8Ib0xmfBkXCHeyNLzqVGcvovdjyP05KcGtt+hf7rX+dl6xI4nOpw4ae0IvKskAcqt9qSx9wjn6iOSxlFkQ6t9a3drCQ5oLjzfhlPPZ9mUYIs1k2XYGoAQmGx6T5o29V0Xkdq7/AUCl0Yd4oYG0fm6UoA2QQIDAQAB"
    val privateKeyStr = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIIxydoVMPld5ryn03whvTGZ8GRcId7I0vOpUZy+i92PI/Tkpwa236F/utf52XrEjic6nDhp7Qi8qyQByq32pLH3COfqI5LGUWRDq31rd2sJDmguPN+GU89n2ZRgizWTZdgagBCYbHpPmjb1XReR2rv8BQKXRh3ihgbR+bpSgDZBAgMBAAECgYAPYEnyk6YhDVH+3eNAOcvaW8/kSm1FnnorhMe6t1ZVaF5awdZoGJj4vdkXQM7KjQQs5eMlVn1EFuQvcHa7bPGuV3n75xuA/nymM2AOqAWRtiTch4ZhOIbRJlHI88FztMI5YtBQHg5Yz3bdg38ZTHfexiF84Hg/wxui3KKPnaIpsQJBANBylDN+opVkowE6tCGX8rBPvLdzJfVQtQ55vBfqH7Uwu3Bvqg0JMPdwJ+JieCc17SYd4+Eoz5942rdhuMMmoMMCQQCf5TK8FpSS55KOkg8CBtaNtj8ZBgdlFlz9l/bLQwnBb0C/cMAIdj4r2sdr/xg4dqkQXuJRZap/AM2iBYq/lJyrAkBpBUFrzGKnuCN0TBpTTpYEhLgFCWvXdAk0uNquhdPh2yKk3G2l0bqtAAHoSkpVHxNTf/2/BGvO4fn4KLEJCZ43AkBkdSS+BVXNQk7S4jMpq9Aq8sCL4TzOJxG/hjVZGUJM1LASVy1fY6LF/MtkL74w42Ru055PU5ed+Yw4alD08tLHAkEAhh9Bjw6pxeCxCFIwK2FQ9jOz+IOhstr2+gIxPaCQg/x5TLwpf9asQdp11Qut5s990kdronZH99VjLeZiwIj/6A=="

    //字符串转成秘钥对对象
    val kf = KeyFactory.getInstance("RSA")

    val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(privateKeyStr)))
    val publicKey =  kf.generatePublic(X509EncodedKeySpec (Base64.decode(publicKeyStr)))
    println()
    println()
    println()

    /**
     * 秘钥对加密及解密
     * 注：由于秘钥对加密时间过长，所以对长度有一定的要求，长度限制在117字节，可以采用的方法是分段加密
     */
    entryptAnddetrypt(privateKey,publicKey)
}


fun entryptAnddetrypt(privateKey: PrivateKey,publicKey: PublicKey){
    val input = "这是我的加密RSA信息"
    println("/**********************私钥加密  公钥解密**************************/")
    val encrypt = RSACrypt.entryptByPrivateKey(input, privateKey)
    println("私钥加密信息：$encrypt")
    val detrypt = RSACrypt.detryptByPublicKey(encrypt, publicKey)
    println("公钥解密信息：$detrypt")
    println()
    println()
    println()


    println("/*******************公钥加密  私钥解密*************************/")
    val entryptByPublicKey = RSACrypt.entryptByPublicKey(input, publicKey)
    println("公钥加密信息：$entryptByPublicKey")
    val detryptByPrivateKey = RSACrypt.detryptByPrivateKey(entryptByPublicKey, privateKey)
    println("私钥解密信息：$detryptByPrivateKey")
}