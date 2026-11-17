[app]
title = ProxyGUI
package.name = proxygui
package.domain = org.proxygui
source.dir = .
source.include_exts = py,png,jpg,kv,txt
version = 1.0
requirements = python3,kivy
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,POST_NOTIFICATIONS
android.api = 34
android.minapi = 24
android.archs = arm64-v8a,armeabi-v7a
presplash.color = #1e1e24
window.resize_with_keyboard = 1

[buildozer]
log_level = 2
warn_on_root = 1
