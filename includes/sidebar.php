<aside class="w-64 bg-gray-900 text-white min-h-screen flex flex-col transition-all duration-300 md:relative absolute z-10 hidden md:flex" id="sidebar">
    <div class="p-6 text-2xl font-bold tracking-widest border-b border-gray-800">
        <span class="text-blue-500">CHROMA</span> IT
    </div>
    <nav class="flex-1 px-4 py-6 space-y-2">
        <a href="dashboard.php" class="block px-4 py-3 rounded-lg hover:bg-gray-800 transition">📊 Dashboard</a>
        <a href="upload.php" class="block px-4 py-3 rounded-lg hover:bg-gray-800 transition">📤 Upload Syslog</a>
        <a href="settings.php" class="block px-4 py-3 rounded-lg hover:bg-gray-800 transition">⚙️ Settings</a>
    </nav>
    <div class="p-4 border-t border-gray-800">
        <a href="logout.php" class="block px-4 py-2 text-center bg-red-600 rounded-lg hover:bg-red-700 transition">Logout</a>
    </div>
</aside>

<script>
    // Mobile menu toggle logic
    function toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.toggle('hidden');
    }
</script>