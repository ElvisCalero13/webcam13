package local.hdcamerapro.bridge;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.graphics.Path;
import android.os.Handler;
import android.os.Looper;
import android.view.accessibility.AccessibilityEvent;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class RemoteControlService extends AccessibilityService {
    private static final int PORT = 18787;
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean running;
    private ServerSocket listener;

    @Override protected void onServiceConnected() {
        super.onServiceConnected();
        running = true;
        Thread server = new Thread(this::serve, "HDCameraControlBridge");
        server.setDaemon(true);
        server.start();
    }

    @Override public void onAccessibilityEvent(AccessibilityEvent event) { }
    @Override public void onInterrupt() { }

    @Override public void onDestroy() {
        running = false;
        try { if (listener != null) listener.close(); } catch (Exception ignored) { }
        super.onDestroy();
    }

    private void serve() {
        try (ServerSocket server = new ServerSocket(PORT, 4, InetAddress.getByName("127.0.0.1"))) {
            listener = server;
            while (running) {
                try (Socket client = server.accept()) {
                    client.setSoTimeout(5000);
                    BufferedReader input = new BufferedReader(new InputStreamReader(client.getInputStream(), "UTF-8"));
                    BufferedWriter output = new BufferedWriter(new OutputStreamWriter(client.getOutputStream(), "UTF-8"));
                    String line = input.readLine();
                    JSONObject reply;
                    if (line == null || line.length() > 4096) reply = error("Solicitud vacía o demasiado grande.");
                    else reply = execute(new JSONObject(line));
                    output.write(reply.toString());
                    output.write('\n');
                    output.flush();
                } catch (Exception ignored) { }
            }
        } catch (Exception ignored) {
            running = false;
        }
    }

    private JSONObject execute(JSONObject command) {
        String type = command.optString("type", "");
        if ("ping".equals(type)) return ok("ready");
        if ("key".equals(type)) {
            String key = command.optString("key", "");
            final int action;
            if ("back".equals(key)) action = GLOBAL_ACTION_BACK;
            else if ("home".equals(key)) action = GLOBAL_ACTION_HOME;
            else return error("Tecla no admitida.");
            return onMain(() -> performGlobalAction(action) ? ok("key") : error("Android no aceptó la tecla."));
        }
        if (!"tap".equals(type) && !"swipe".equals(type)) return error("Acción desconocida.");
        float x1 = command.optInt("x", command.optInt("x1", -1));
        float y1 = command.optInt("y", command.optInt("y1", -1));
        float x2 = command.optInt("x2", (int) x1);
        float y2 = command.optInt("y2", (int) y1);
        int duration = "tap".equals(type) ? 120 : command.optInt("duration", 350);
        if (x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0 || duration < 50 || duration > 2000) return error("Coordenadas o duración inválidas.");

        Path path = new Path();
        path.moveTo(x1, y1);
        path.lineTo(x2, y2);
        GestureDescription gesture = new GestureDescription.Builder()
                .addStroke(new GestureDescription.StrokeDescription(path, 0, duration)).build();
        CountDownLatch gestureDone = new CountDownLatch(1);
        AtomicReference<JSONObject> gestureResult = new AtomicReference<>(error("Android rechazó el gesto."));
        main.post(() -> {
            boolean accepted = dispatchGesture(gesture, new GestureResultCallback() {
                @Override public void onCompleted(GestureDescription description) { gestureResult.set(ok(type)); gestureDone.countDown(); }
                @Override public void onCancelled(GestureDescription description) { gestureResult.set(error("Android canceló el gesto.")); gestureDone.countDown(); }
            }, main);
            if (!accepted) { gestureResult.set(error("No se pudo iniciar el gesto de accesibilidad.")); gestureDone.countDown(); }
        });
        try {
            if (!gestureDone.await(5, TimeUnit.SECONDS)) return error("Tiempo agotado esperando el gesto.");
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); return error("Gesto interrumpido."); }
        return gestureResult.get();
    }

    private JSONObject onMain(java.util.concurrent.Callable<JSONObject> action) {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<JSONObject> result = new AtomicReference<>(error("No se completó la acción."));
        main.post(() -> {
            try { result.set(action.call()); }
            catch (Exception e) { result.set(error(e.getMessage() == null ? "Error interno." : e.getMessage())); }
            finally { done.countDown(); }
        });
        try {
            if (!done.await(6, TimeUnit.SECONDS)) return error("Tiempo agotado esperando Android.");
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); return error("Acción interrumpida."); }
        return result.get();
    }

    private static JSONObject ok(String action) {
        JSONObject value = new JSONObject();
        try { value.put("ok", true); value.put("action", action); } catch (Exception ignored) { }
        return value;
    }

    private static JSONObject error(String message) {
        JSONObject value = new JSONObject();
        try { value.put("ok", false); value.put("error", message); } catch (Exception ignored) { }
        return value;
    }
}
