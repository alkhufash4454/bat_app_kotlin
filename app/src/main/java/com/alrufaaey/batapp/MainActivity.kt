package com.alrufaaey.batapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.text.method.ScrollingMovementMethod
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.alrufaaey.batapp.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var hostsAdapter: HostsAdapter
    private val hostsList = mutableListOf<String>()

    private var attackService: AttackService? = null
    private var isBound = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as AttackService.LocalBinder
            attackService = binder.getService()
            isBound = true
            observeServiceData()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            attackService = null
            isBound = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = "الخفاش - أداة الاختبار المطورة"

        binding.tvLog.movementMethod = ScrollingMovementMethod()

        setupRecyclerView()
        setupClickListeners()
        loadHosts()
        startAndBindService()
    }

    private fun startAndBindService() {
        val intent = Intent(this, AttackService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(this, intent)
        } else {
            startService(intent)
        }
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private fun setupRecyclerView() {
        hostsAdapter = HostsAdapter(hostsList) { host ->
            binding.etTargetUrl.setText(host)
        }
        binding.rvHosts.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = hostsAdapter
        }
    }

    private fun setupClickListeners() {
        binding.btnStart.setOnClickListener {
            startAttack()
        }

        binding.btnStop.setOnClickListener {
            stopAttack()
        }

        binding.btnAddHost.setOnClickListener {
            addNewHost()
        }
    }

    private fun startAttack() {
        val target = binding.etTargetUrl.text.toString().trim()
        if (target.isEmpty()) {
            Toast.makeText(this, "أدخل عنوان الهدف", Toast.LENGTH_SHORT).show()
            return
        }

        val isHttps = binding.switchHttps.isChecked
        val threads = binding.etThreads.text.toString().toIntOrNull() ?: 100
        val hours = binding.etHours.text.toString().toIntOrNull() ?: 1
        val customProxy = binding.etCustomProxy.text.toString().trim()

        // إذا تم إدخال بروكسي مخصص، نضيفه للقائمة
        if (customProxy.isNotEmpty() && customProxy.contains(":")) {
            // يمكن تمريره عبر الـ Intent أو تحديث الـ Config (بشكل مؤقت هنا)
            // ملاحظة: للتطبيق الفعلي يفضل استخدام SharedPreferences للبروكسي المخصص
        }

        attackService?.startAttack(target, isHttps, threads, hours)
    }

    private fun stopAttack() {
        attackService?.stopAttack()
    }

    private fun addNewHost() {
        val newHost = binding.etNewHost.text.toString().trim()
        if (newHost.isNotEmpty() && !hostsList.contains(newHost)) {
            hostsList.add(newHost)
            hostsAdapter.notifyItemInserted(hostsList.size - 1)
            saveHosts()
            binding.etNewHost.text?.clear()
            Toast.makeText(this, "تم إضافة: $newHost", Toast.LENGTH_SHORT).show()
        }
    }

    private fun observeServiceData() {
        attackService?.let { service ->
            lifecycleScope.launch {
                service.isAttacking.collect { isAttacking ->
                    updateUiState(isAttacking)
                }
            }
            lifecycleScope.launch {
                service.totalRequests.collect { total ->
                    binding.tvStats.text = "إجمالي الطلبات: ${String.format("%,d", total)}"
                }
            }
            lifecycleScope.launch {
                service.logMessages.collect { message ->
                    val currentLog = binding.tvLog.text.toString()
                    val lines = currentLog.split("\n").toMutableList()
                    if (lines.size > 100) lines.removeAt(0)
                    lines.add(message)
                    binding.tvLog.text = lines.joinToString("\n")
                    
                    // التمرير التلقائي لأسفل
                    val scrollAmount = binding.tvLog.layout?.getLineTop(binding.tvLog.lineCount) ?: 0
                    if (scrollAmount > binding.tvLog.height) {
                        binding.tvLog.scrollTo(0, scrollAmount - binding.tvLog.height)
                    }
                }
            }
        }
    }

    private fun updateUiState(isAttacking: Boolean) {
        if (isAttacking) {
            binding.btnStart.isEnabled = false
            binding.btnStop.isEnabled = true
            binding.tvStatus.text = "الحالة: نشط"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_green_light))
        } else {
            binding.btnStart.isEnabled = true
            binding.btnStop.isEnabled = false
            binding.tvStatus.text = "الحالة: متوقف"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_red_light))
        }
    }

    private fun loadHosts() {
        val prefs = getSharedPreferences("bat_app_prefs", Context.MODE_PRIVATE)
        val hostsSet = prefs.getStringSet("hosts", emptySet()) ?: emptySet()
        hostsList.clear()
        hostsList.addAll(hostsSet.toList())
        hostsAdapter.notifyDataSetChanged()
    }

    private fun saveHosts() {
        val prefs = getSharedPreferences("bat_app_prefs", Context.MODE_PRIVATE)
        prefs.edit().putStringSet("hosts", hostsList.toSet()).apply()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_logs -> {
                showLogsDialog()
                true
            }
            R.id.menu_settings -> {
                showSettingsDialog()
                true
            }
            R.id.menu_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showLogsDialog() {
        val logText = if (hostsList.isEmpty()) "لا توجد هوستات مسجلة"
        else hostsList.takeLast(10).mapIndexed { i, h -> "${i + 1}. $h" }.joinToString("\n")
        AlertDialog.Builder(this)
            .setTitle("آخر الهوستات")
            .setMessage(logText)
            .setPositiveButton("حسناً", null)
            .show()
    }

    private fun showSettingsDialog() {
        val settingsText = """
            Proxies: ${AttackConfig.PROXIES.size} متوفرة
            وضع الهجوم: TURBO + Response Logging
            توافق الشبكة: شامل (IPv4/IPv6 Ready)
            استهلاك البطارية: محسن
        """.trimIndent()
        AlertDialog.Builder(this)
            .setTitle("الإعدادات")
            .setMessage(settingsText)
            .setPositiveButton("حسناً", null)
            .show()
    }

    private fun showAboutDialog() {
        val aboutText = """
            تطبيق الخفاش - النسخة المطورة
            
            أداة احترافية لاختبار استجابة الخوادم
            مع دعم 50 بروكسي وسجلات حية.
            
            ⚠️ للأغراض التعليمية فقط
            
            الإصدار: 2.0
            المطور: @alrufaaey
        """.trimIndent()
        AlertDialog.Builder(this)
            .setTitle("حول التطبيق")
            .setMessage(aboutText)
            .setPositiveButton("حسناً", null)
            .show()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }
}
