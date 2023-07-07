package org.example;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.net.URL;
import java.text.SimpleDateFormat;
import javax.net.ssl.HttpsURLConnection;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.lang.reflect.Field;
public class Main {
    public static void main(String[] args) {
        String fileName = "url_list.txt";

        String filePath = System.getProperty("user.dir") + File.separator + fileName;
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            // DNS 임시 변경
            //String dnsServer = "8.8.8.8";
            //changeDNS(dnsServer);

            String line;
            while ((line = reader.readLine()) != null) {
                if(!line.startsWith("#")){
                    line = line.trim();
                    if (!line.isEmpty()) {
                        processURL(line);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    private static void processURL(String url) {
        try {
            // 인증서 검증 비활성화
            disableCertificateValidation();
            int connectionTimeout = 3000; // 연결 타임아웃 (5초)
            int readTimeout = 3000; // 읽기 타임아웃 (10초)

            System.out.print("Checking : "+url +" ... ");
            URL serverURL = new URL(url);
            HttpsURLConnection conn = (HttpsURLConnection) serverURL.openConnection();
            conn.setConnectTimeout(connectionTimeout);
            conn.setReadTimeout(readTimeout);
            conn.connect();
            Certificate[] certs = conn.getServerCertificates();

            // 첫 번째 인증서는 최상위 인증서
            X509Certificate rootCert = (X509Certificate) certs[0];
            String rootExpirationDate = formatDate(rootCert.getNotAfter());
            long rootDaysRemaining = getDaysRemaining(rootCert.getNotAfter());
            System.out.print("(" + rootExpirationDate+"/"+rootDaysRemaining + "일) ");
            for (int i = 1; i < certs.length; i++) {
                X509Certificate intermediateCert = (X509Certificate) certs[i];
                String intermediateExpirationDate = formatDate(intermediateCert.getNotAfter());
                long intermediateDaysRemaining = getDaysRemaining(intermediateCert.getNotAfter());
                System.out.print("(" + intermediateExpirationDate+"/"+intermediateDaysRemaining + "일) ");
            }
            System.out.println("");
            conn.disconnect();
        } catch (IOException e) {
            //e.printStackTrace();
            if(e.toString().length() > 100){
                System.out.println(e.toString().substring(0,99));
            }else{
                System.out.println(e.toString());
            }
        }
    }
    private static void disableCertificateValidation() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static String formatDate(java.util.Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(date);
    }
    private static void changeDNS(String dnsServer) {
        try {
            // DNS 변경
            System.setProperty("sun.net.spi.nameservice.nameservers", dnsServer);
            System.setProperty("sun.net.spi.nameservice.provider.1", "dns,sun");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void removeDNS() {
        try {
            String propertyKey = "sun.net.spi.nameservice.nameservers";

            // System 클래스의 유형과 속성 필드 검색
            Class<?> systemClass = Class.forName("java.lang.System");
            Field propertiesField = systemClass.getDeclaredField("props");
            propertiesField.setAccessible(true);
            Object properties = propertiesField.get(null);

            // 속성에서 특정 키 삭제
            Class<?> propertiesClass = properties.getClass();
            Field defaultsField = propertiesClass.getDeclaredField("defaults");
            defaultsField.setAccessible(true);
            Object defaults = defaultsField.get(properties);

            Class<?> defaultsClass = defaults.getClass();
            Field propsField = defaultsClass.getDeclaredField("props");
            propsField.setAccessible(true);
            Object props = propsField.get(defaults);

            Class<?> propsClass = props.getClass();
            Field propertyField = propsClass.getDeclaredField(propertyKey);
            propertyField.setAccessible(true);
            propertyField.set(props, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static long getDaysRemaining(Date expirationDate) {
        long currentTimeMillis = System.currentTimeMillis();
        long expirationTimeMillis = expirationDate.getTime();
        long remainingMillis = expirationTimeMillis - currentTimeMillis;
        return TimeUnit.MILLISECONDS.toDays(remainingMillis);
    }

}
