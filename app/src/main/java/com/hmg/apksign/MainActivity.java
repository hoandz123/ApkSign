package com.hmg.apksign;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.hmg.apksign.databinding.ActivityMainBinding;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_PICK_FILE = 1001;
    
    static {
        System.loadLibrary("apksign");
    }

    private ActivityMainBinding binding;
    private String selectedFilePath = null;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        mainHandler = new Handler(Looper.getMainLooper());

        setupToolbar();
        setupButtons();
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        // Activity không bị recreate, dữ liệu được giữ nguyên
    }

    private void setupToolbar() {
        setSupportActionBar(binding.toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayShowTitleEnabled(true);
        }
    }

    private void setupButtons() {
        binding.btnPickFile.setOnClickListener(v -> pickApkFile());
        binding.btnVerify.setOnClickListener(v -> verifyApkSignature());
        binding.btnCopyCert.setOnClickListener(v -> copyCertificate());
    }

    private void pickApkFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/vnd.android.package-archive");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, "Select APK File"), REQUEST_CODE_PICK_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == REQUEST_CODE_PICK_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                handleSelectedFile(uri);
            }
        }
    }

    private void handleSelectedFile(Uri uri) {
        try {
            String fileName = getFileName(uri);
            File tempFile = new File(getCacheDir(), fileName);
            
            InputStream inputStream = getContentResolver().openInputStream(uri);
            FileOutputStream outputStream = new FileOutputStream(tempFile);
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            
            inputStream.close();
            outputStream.close();
            
            selectedFilePath = tempFile.getAbsolutePath();
            binding.tvFilePath.setText(selectedFilePath);
            binding.btnVerify.setEnabled(true);
            
            hideResults();
            Toast.makeText(this, "File selected: " + fileName, Toast.LENGTH_SHORT).show();
            
        } catch (Exception e) {
            Toast.makeText(this, "Error reading file: " + e.getMessage(), Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
            try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                    if (nameIndex >= 0) {
                        result = cursor.getString(nameIndex);
                    }
                }
            }
        }
        if (result == null) {
            result = uri.getPath();
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result != null ? result : "selected.apk";
    }

    private void verifyApkSignature() {
        if (selectedFilePath == null || selectedFilePath.isEmpty()) {
            Toast.makeText(this, "Please select an APK file first", Toast.LENGTH_SHORT).show();
            return;
        }

        binding.progressBar.setVisibility(View.VISIBLE);
        binding.btnVerify.setEnabled(false);
        hideResults();

        new Thread(() -> {
            try {
                String resultJson = verifyApkSignature(selectedFilePath);
                mainHandler.post(() -> displayResult(resultJson));
            } catch (Exception e) {
                mainHandler.post(() -> {
                    binding.progressBar.setVisibility(View.GONE);
                    binding.btnVerify.setEnabled(true);
                    Toast.makeText(MainActivity.this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    private void displayResult(String resultJson) {
        binding.progressBar.setVisibility(View.GONE);
        binding.btnVerify.setEnabled(true);
        binding.cardResult.setVisibility(View.VISIBLE);

        try {
            JSONObject json = new JSONObject(resultJson);
            boolean success = json.optBoolean("success", false);
            String errorMessage = json.optString("error_message", "");
            int signatureBlocksCount = json.optInt("signature_blocks_count", 0);
            int certificatesCount = json.optInt("certificates_count", 0);
            String certificateBase64 = json.optString("first_certificate_base64", "");

            ImageView statusIcon = binding.ivStatus;
            TextView statusText = binding.tvStatus;
            TextView resultText = binding.tvResult;

            if (success) {
                statusIcon.setImageResource(android.R.drawable.checkbox_on_background);
                statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.success));
                statusText.setText("Verification Successful");
                statusText.setTextColor(ContextCompat.getColor(this, R.color.success));
                binding.layoutStatus.setBackgroundColor(ContextCompat.getColor(this, R.color.success));
                binding.layoutStatus.getBackground().setAlpha(20);
            } else {
                statusIcon.setImageResource(android.R.drawable.ic_dialog_alert);
                statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.error));
                statusText.setText("Verification Failed");
                statusText.setTextColor(ContextCompat.getColor(this, R.color.error));
                binding.layoutStatus.setBackgroundColor(ContextCompat.getColor(this, R.color.error_container));
            }

            StringBuilder resultBuilder = new StringBuilder();
            resultBuilder.append("Status: ").append(success ? "SUCCESS" : "FAILED").append("\n\n");
            if (!errorMessage.isEmpty()) {
                resultBuilder.append("Error: ").append(errorMessage).append("\n\n");
            }
            resultBuilder.append("Signature Blocks: ").append(signatureBlocksCount).append("\n");
            resultBuilder.append("Certificates Found: ").append(certificatesCount).append("\n");

            resultText.setText(resultBuilder.toString());

            if (!certificateBase64.isEmpty()) {
                binding.cardCertificate.setVisibility(View.VISIBLE);
                binding.tvCertificate.setText(certificateBase64);
            } else {
                binding.cardCertificate.setVisibility(View.GONE);
            }

        } catch (Exception e) {
            binding.tvResult.setText("Error parsing result: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void hideResults() {
        binding.cardResult.setVisibility(View.GONE);
        binding.cardCertificate.setVisibility(View.GONE);
    }

    private void copyCertificate() {
        String certificate = binding.tvCertificate.getText().toString();
        if (certificate.isEmpty()) {
            Toast.makeText(this, "No certificate to copy", Toast.LENGTH_SHORT).show();
            return;
        }

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Certificate", certificate);
        clipboard.setPrimaryClip(clip);
        Toast.makeText(this, "Certificate copied to clipboard", Toast.LENGTH_SHORT).show();
    }

    public native String stringFromJNI();
    
    public native String verifyApkSignature(String apkPath);
    
    public native String getCertificateBase64(String apkPath);
}
