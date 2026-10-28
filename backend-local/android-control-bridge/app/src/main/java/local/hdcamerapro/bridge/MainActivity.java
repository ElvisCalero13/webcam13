package local.hdcamerapro.bridge;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.provider.Settings;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private TextView state;

    @Override public void onCreate(android.os.Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(28, 32, 28, 24);
        root.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText("Puente de control local");
        title.setTextSize(24);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));

        TextView instructions = new TextView(this);
        instructions.setText("Para que la web controle el teléfono, Android requiere habilitar este servicio de accesibilidad. No lee ni transmite el contenido de otras apps; solo ejecuta los toques, gestos y teclas que envía el backend local por el cable USB.");
        instructions.setTextSize(16);
        LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(-1, -2);
        ip.topMargin = 20;
        root.addView(instructions, ip);

        state = new TextView(this);
        state.setTextSize(16);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(-1, -2);
        sp.topMargin = 24;
        root.addView(state, sp);

        Button settings = new Button(this);
        settings.setText("Abrir ajustes de accesibilidad");
        settings.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, -2);
        bp.topMargin = 16;
        root.addView(settings, bp);

        TextView help = new TextView(this);
        help.setText("En Ajustes, activa “Control local HDCameraPro” y confirma el aviso del sistema. Luego vuelve a esta app. Mantén el teléfono conectado por USB y el backend abierto en la laptop.");
        help.setTextSize(14);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(-1, -2);
        hp.topMargin = 16;
        root.addView(help, hp);
        setContentView(root, new ViewGroup.LayoutParams(-1, -1));
        refreshState();
    }

    @Override protected void onResume() { super.onResume(); refreshState(); }

    private void refreshState() {
        ComponentName component = new ComponentName(this, RemoteControlService.class);
        String enabled = Settings.Secure.getString(getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        boolean active = enabled != null && enabled.toLowerCase().contains(component.flattenToString().toLowerCase());
        state.setText(active ? "Estado: servicio habilitado. Regresa a la web y prueba los controles."
                : "Estado: falta habilitar el servicio en Ajustes.");
    }
}
