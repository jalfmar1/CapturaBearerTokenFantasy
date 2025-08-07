// Frida: Bypass root detection + captura de intents y tráfico HTTP + guarda en archivo y exporta Bearer

var logFile = "/data/data/com.lfp.laligafantasy/frida_capture.log";
var logs = [];
var lastBearer = null;

function log(msg) {
    var now = new Date().toISOString();
    logs.push(`[${now}] ${msg}`);
    console.log(msg);
    // Extrae el último Bearer token
    var m = msg.match(/Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)/);
    if (m && m[1]) {
        lastBearer = m[1];
        // Guarda el log inmediatamente cuando se captura un Bearer
        Java.perform(function() { saveLogs(); });
    }
}

function saveLogs() {
    try {
        var File = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
        var file = File.$new(logFile);
        var fos = FileOutputStream.$new.overload('java.io.File').call(FileOutputStream, file);
        var writer = OutputStreamWriter.$new(fos);
        for (var i = 0; i < logs.length; i++) {
            var line = logs[i] + "\n";
            writer.write(line, 0, line.length);
        }
        // Añade el Bearer al final en formato env si existe
        if (lastBearer) {
            var bearerLine = "\nBEARER_TOKEN=" + lastBearer + "\n";
            writer.write(bearerLine, 0, bearerLine.length);
        }
        writer.close();
        fos.close();
        console.log("[*] Logs guardados en " + logFile);
    } catch (e) {
        console.log("[!] Error guardando logs: " + e);
    }
}

function saveBearerToEnv() {
    if (!lastBearer) {
        console.log("[!] No se ha capturado ningún token Bearer.");
        return;
    }
    send({bearer: lastBearer});
}

Java.perform(function () {
    // --- UNROOT HOOKS ---
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        if (name.indexOf("su") !== -1 || name.indexOf("busybox") !== -1 || name.indexOf("magisk") !== -1) {
            return false;
        }
        return this.exists.call(this);
    };

    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String').implementation = function(name) {
        if (name === "ro.build.tags") return "release-keys";
        return this.get.call(this, name);
    };

    var Build = Java.use("android.os.Build");
    Object.defineProperty(Build, "TAGS", {
        get: function() { return "release-keys"; }
    });

    var pm = Java.use("android.app.ApplicationPackageManager");
    pm.getInstalledPackages.overload('int').implementation = function(flags) {
        var pkgs = this.getInstalledPackages.call(this, flags);
        var newList = Java.use("java.util.ArrayList").$new();
        for (var i = 0; i < pkgs.size(); i++) {
            var pkg = pkgs.get(i);
            var name = pkg.packageName.value;
            if (name.indexOf("superuser") === -1 && name.indexOf("supersu") === -1 && name.indexOf("magisk") === -1) {
                newList.add(pkg);
            }
        }
        return newList;
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd === "su") {
            throw "Permission denied";
        }
        return this.exec.call(this, cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        if (cmd[0] === "su") {
            throw "Permission denied";
        }
        return this.exec.call(this, cmd);
    };

    var System = Java.use("java.lang.System");
    System.getenv.overload('java.lang.String').implementation = function(name) {
        if (name === "PATH") {
            return "/usr/bin:/bin:/usr/sbin:/sbin";
        }
        return this.getenv.call(this, name);
    };

    // --- CAPTURA INTENTS Y HTTP ---
    var Activity = Java.use('android.app.Activity');
    Activity.onNewIntent.implementation = function (intent) {
        var msg = '[INTENT] onNewIntent recibido:';
        try {
            var data = intent.getDataString();
            msg += "\n  DataString: " + data;
        } catch (e) {}
        log(msg);
        this.onNewIntent.call(this, intent);
    };

    Activity.onActivityResult.implementation = function (requestCode, resultCode, data) {
        var msg = '[INTENT] onActivityResult recibido:';
        try {
            if (data) {
                var extras = data.getExtras();
                if (extras) {
                    var keys = extras.keySet().toArray();
                    for (var i = 0; i < keys.length; i++) {
                        var key = keys[i];
                        msg += "\n  Extra: " + key + " = " + extras.get(key);
                    }
                }
                var uri = data.getDataString();
                if (uri) msg += "\n  DataString: " + uri;
            }
        } catch (e) {}
        log(msg);
        this.onActivityResult.call(this, requestCode, resultCode, data);
    };

    // --- OKHTTP3: PETICIONES ---
    try {
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var req = this.request();
            var msg = '[OKHTTP REQUEST]\n';
            msg += '  URL: ' + req.url().toString() + '\n';
            msg += '  Method: ' + req.method() + '\n';
            var headers = req.headers();
            for (var i = 0; i < headers.size(); i++) {
                msg += '  Header: ' + headers.name(i) + ': ' + headers.value(i) + '\n';
            }
            var body = req.body();
            if (body) {
                try {
                    var Buffer = Java.use('okio.Buffer');
                    var buffer = Buffer.$new();
                    body.writeTo(buffer);
                    var charset = Java.use('java.nio.charset.Charset').forName('UTF-8');
                    msg += '  Body: ' + buffer.readString(charset) + '\n';
                } catch (e) {
                    msg += '  Body: <no se pudo leer>\n';
                }
            }
            log(msg);
            return this.execute.call(this);
        };
    } catch (e) {}

    // --- HTTPURLCONNECTION: PETICIONES ---
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function () {
            var msg = '[HTTPURLCONNECTION REQUEST]\n';
            try {
                msg += '  URL: ' + this.getURL().toString() + '\n';
                msg += '  Method: ' + this.getRequestMethod() + '\n';
                var fields = this.getRequestProperties();
                var keys = fields.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i];
                    msg += '  Header: ' + key + ': ' + fields.get(key) + '\n';
                }
            } catch (e) {}
            log(msg);
            return this.connect.call(this);
        };
    } catch (e) {}

    // --- VOLLEY ---
    try {
        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        HurlStack.executeRequest.implementation = function(request, additionalHeaders) {
            var msg = '[VOLLEY REQUEST]\n';
            try {
                msg += '  URL: ' + request.getUrl() + '\n';
                msg += '  Method: ' + request.getMethod() + '\n';
                msg += '  Headers: ' + JSON.stringify(additionalHeaders) + '\n';
            } catch (e) {}
            log(msg);
            return this.executeRequest.call(this, request, additionalHeaders);
        };
    } catch (e) {}

    // --- APACHE HTTPCLIENT ---
    try {
        var HttpRequestBase = Java.use('org.apache.http.client.methods.HttpRequestBase');
        HttpRequestBase.getURI.implementation = function() {
            var msg = '[APACHE HTTPCLIENT REQUEST]\n';
            try {
                msg += '  URI: ' + this.getURI().toString() + '\n';
                msg += '  Method: ' + this.getMethod() + '\n';
            } catch (e) {}
            log(msg);
            return this.getURI.call(this);
        };
    } catch (e) {}

    // --- WEBVIEW: JS XHR/FETCH ---
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function(script, callback) {
            log('[WEBVIEW JS] ' + script);
            return this.evaluateJavascript.call(this, script, callback);
        };
    } catch (e) {}
});


// Guardar logs y exportar Bearer al salir (CTRL+C en Frida)
rpc.exports = {
    savelogs: function () {
        Java.perform(saveLogs);
    },
    savebearer: function () {
        Java.perform(saveBearerToEnv);
    }
};

function exitHandler() {
    Java.perform(function() {
        saveLogs();
        saveBearerToEnv();
    });
    setTimeout(function() { Process.exit(); }, 1000);
}

['SIGINT', 'SIGTERM'].forEach(function(sig) {
    process.on(sig, exitHandler);
});

// Recibe el token en el host y lo guarda en .env.local
if (typeof recv === "function") {
    recv(function onMessage(msg) {
        if (msg.payload && msg.payload.bearer) {
            var fs = require('fs');
            var envPath = "../../.env.local"; // Ajusta la ruta si tu estructura es diferente
            var envLine = "BEARER_TOKEN=" + msg.payload.bearer + "\n";
            try {
                fs.writeFileSync(envPath, envLine, {flag: 'w'});
                console.log("[*] Bearer guardado en " + envPath);
            } catch (e) {
                console.log("[!] Error guardando el Bearer en .env.local: " + e);
            }
        }
    });
}

// Guarda el log cuando el proceso Java se va a descargar (app cerrada)
Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.addShutdownHook.implementation = function(hook) {
        saveLogs();
        return this.addShutdownHook.call(this, hook);
    };
});