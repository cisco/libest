import java.security.Certificate;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;



public class MyTrustManager implements X509TrustManager {

    X509TrustManager pkixTrustManager;

    MyTrustManager(KeyStore ks) throws Exception {

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
        trustManagerFactory.init(ks);

        TrustManager trustManagers[] = trustManagerFactory.getTrustManagers();

        for(TrustManager trustManager : trustManagers) {
            if(trustManager instanceof X509TrustManager) {
                pkixTrustManager = (X509TrustManager) trustManager;
                return;
            }
        }

        throw new Exception("Couldn't initialize");
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        pkixTrustManager.checkServerTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        pkixTrustManager.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return pkixTrustManager.getAcceptedIssuers();
    }
}