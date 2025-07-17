import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

interface AnalysisRequest {
  type: 'apk' | 'playstore';
  data: string; // base64 APK data or Play Store URL
  filename?: string;
}

interface SecurityIssue {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  recommendation: string;
  owaspCategory: string;
  technicalDetails: string;
  codeExample?: string;
  references: string[];
  location?: string;
  cwe?: string;
}

interface AnalysisResult {
  id: string;
  appName: string;
  packageName: string;
  version: string;
  securityScore: number;
  issues: SecurityIssue[];
  analysisDate: string;
  fileSize?: number;
  analysisTime: number;
  owaspCoverage: {
    category: string;
    issues: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }[];
  permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  minSdkVersion?: number;
  targetSdkVersion?: number;
  certificates: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    algorithm: string;
  }[];
}

const OWASP_CATEGORIES = [
  'M1: Improper Platform Usage',
  'M2: Insecure Data Storage', 
  'M3: Insecure Communication',
  'M4: Insecure Authentication',
  'M5: Insufficient Cryptography',
  'M6: Insecure Authorization',
  'M7: Client Code Quality',
  'M8: Code Tampering',
  'M9: Reverse Engineering',
  'M10: Extraneous Functionality'
];

// Mock security analysis for demonstration
async function analyzeAPK(apkData: string, filename: string): Promise<AnalysisResult> {
  const startTime = Date.now();
  const analysisId = `analysis_${Date.now()}`;
  
  try {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Decode base64 to get file size
    const apkBuffer = Uint8Array.from(atob(apkData), c => c.charCodeAt(0));
    
    // Extract package name from filename or generate one
    const packageName = filename.includes('.') 
      ? `com.example.${filename.replace('.apk', '').toLowerCase().replace(/[^a-z0-9]/g, '')}`
      : 'com.example.app';
    
    const appName = filename.replace('.apk', '').replace(/[_-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    
    // Generate realistic security issues based on common vulnerabilities
    const issues: SecurityIssue[] = [
      {
        id: `issue_${Date.now()}_1`,
        title: 'Insecure Data Storage in SharedPreferences',
        severity: 'high',
        category: 'Data Protection',
        description: 'Sensitive data is stored in SharedPreferences without encryption, making it accessible to other apps with root access or through backup mechanisms.',
        recommendation: 'Encrypt sensitive data before storing in SharedPreferences using Android Keystore or implement secure storage solutions like EncryptedSharedPreferences.',
        owaspCategory: 'M2: Insecure Data Storage',
        technicalDetails: 'SharedPreferences files are stored in plain text in /data/data/[package]/shared_prefs/ and can be accessed by rooted devices or through ADB backup.',
        codeExample: `// Vulnerable code
SharedPreferences prefs = getSharedPreferences("user_data", MODE_PRIVATE);
prefs.edit().putString("password", userPassword).apply();

// Secure alternative
EncryptedSharedPreferences encryptedPrefs = EncryptedSharedPreferences.create(
    "secure_prefs",
    MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
encryptedPrefs.edit().putString("password", userPassword).apply();`,
        references: [
          'https://developer.android.com/topic/security/data',
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage'
        ]
      },
      {
        id: `issue_${Date.now()}_2`,
        title: 'Cleartext HTTP Traffic Allowed',
        severity: 'critical',
        category: 'Network Security',
        description: 'Application allows HTTP traffic, making it vulnerable to man-in-the-middle attacks and data interception.',
        recommendation: 'Disable cleartext traffic and implement network security configuration to enforce HTTPS for all communications.',
        owaspCategory: 'M3: Insecure Communication',
        technicalDetails: 'The android:usesCleartextTraffic="true" attribute or lack of network security config allows unencrypted HTTP connections.',
        codeExample: `<!-- AndroidManifest.xml - Secure configuration -->
<application
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config"
    ... >

<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
    </domain-config>
</network-security-config>`,
        references: [
          'https://developer.android.com/training/articles/security-config',
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication'
        ]
      },
      {
        id: `issue_${Date.now()}_3`,
        title: 'Weak Cryptographic Implementation',
        severity: 'high',
        category: 'Cryptography',
        description: 'Application uses deprecated cryptographic algorithms (MD5, SHA1) that are vulnerable to collision attacks.',
        recommendation: 'Replace weak algorithms with SHA-256 or stronger. Use bcrypt, scrypt, or Argon2 for password hashing.',
        owaspCategory: 'M5: Insufficient Cryptography',
        technicalDetails: 'MD5 and SHA1 algorithms are cryptographically broken and should not be used for security-sensitive operations.',
        codeExample: `// Vulnerable code
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// Secure alternative
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
byte[] salt = new byte[16];
new SecureRandom().nextBytes(salt);
byte[] hash = sha256.digest((password + Arrays.toString(salt)).getBytes());`,
        references: [
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
        ]
      },
      {
        id: `issue_${Date.now()}_4`,
        title: 'Debug Mode Enabled in Production',
        severity: 'medium',
        category: 'Code Protection',
        description: 'Application has debugging enabled, allowing attackers to inspect and modify app behavior at runtime.',
        recommendation: 'Ensure android:debuggable="false" in production builds and implement proper build configurations.',
        owaspCategory: 'M8: Code Tampering',
        technicalDetails: 'Debug mode allows runtime inspection, memory dumps, and code modification through debugging tools like GDB.',
        codeExample: `<!-- AndroidManifest.xml - Production configuration -->
<application
    android:debuggable="false"
    ... >

<!-- build.gradle - Use build variants -->
android {
    buildTypes {
        debug {
            debuggable true
        }
        release {
            debuggable false
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}`,
        references: [
          'https://developer.android.com/guide/topics/manifest/application-element#debug',
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering'
        ]
      },
      {
        id: `issue_${Date.now()}_5`,
        title: 'Excessive Dangerous Permissions',
        severity: 'medium',
        category: 'Permissions',
        description: 'Application requests multiple dangerous permissions that may not be necessary for core functionality.',
        recommendation: 'Review and minimize dangerous permissions. Implement runtime permission requests and clearly explain why each permission is needed.',
        owaspCategory: 'M1: Improper Platform Usage',
        technicalDetails: 'Dangerous permissions like CAMERA, LOCATION, READ_CONTACTS provide access to sensitive user data and should be minimized.',
        codeExample: `// Runtime permission request
if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) 
    != PackageManager.PERMISSION_GRANTED) {
    
    if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.CAMERA)) {
        // Show explanation to user
        showPermissionExplanation();
    } else {
        ActivityCompat.requestPermissions(this, 
            new String[]{Manifest.permission.CAMERA}, REQUEST_CAMERA);
    }
}`,
        references: [
          'https://developer.android.com/guide/topics/permissions/overview',
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage'
        ]
      }
    ];
    
    // Calculate security score based on issues
    const securityScore = calculateSecurityScore(issues);
    
    // Generate OWASP coverage
    const owaspCoverage = generateOwaspCoverage(issues);
    
    const analysisTime = Math.round((Date.now() - startTime) / 1000);
    
    return {
      id: analysisId,
      appName,
      packageName,
      version: '1.0.0',
      securityScore,
      issues,
      analysisDate: new Date().toISOString(),
      fileSize: apkBuffer.length,
      analysisTime,
      owaspCoverage,
      permissions: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.CAMERA',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE'
      ],
      activities: ['MainActivity', 'SettingsActivity', 'LoginActivity'],
      services: ['BackgroundService', 'SyncService'],
      receivers: ['BootReceiver', 'NetworkReceiver'],
      minSdkVersion: 21,
      targetSdkVersion: 33,
      certificates: [
        {
          subject: 'CN=Android Debug,O=Android,C=US',
          issuer: 'CN=Android Debug,O=Android,C=US',
          validFrom: '2023-01-01T00:00:00Z',
          validTo: '2024-01-01T00:00:00Z',
          algorithm: 'SHA256withRSA'
        }
      ]
    };
    
  } catch (error) {
    console.error('APK analysis error:', error);
    throw new Error(`Failed to analyze APK: ${error.message}`);
  }
}

async function analyzePlayStoreApp(url: string): Promise<AnalysisResult> {
  const startTime = Date.now();
  
  try {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Extract package name from Play Store URL
    const packageMatch = url.match(/id=([^&]+)/);
    if (!packageMatch) {
      throw new Error('Invalid Play Store URL - could not extract package ID');
    }
    
    const packageName = packageMatch[1];
    const appName = packageName.split('.').pop()?.replace(/[_-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown App';
    
    // Generate realistic security analysis for Play Store app
    const issues: SecurityIssue[] = [
      {
        id: `ps_issue_${Date.now()}_1`,
        title: 'Outdated Target SDK Version',
        severity: 'medium',
        category: 'Platform Security',
        description: 'Application targets an older Android SDK version, missing important security improvements from newer versions.',
        recommendation: 'Update targetSdkVersion to the latest stable Android API level to benefit from enhanced security features.',
        owaspCategory: 'M1: Improper Platform Usage',
        technicalDetails: 'Older SDK versions lack modern security features like scoped storage, runtime permissions improvements, and network security enhancements.',
        codeExample: `// build.gradle
android {
    compileSdkVersion 34
    defaultConfig {
        targetSdkVersion 34  // Update to latest
        minSdkVersion 21
    }
}`,
        references: [
          'https://developer.android.com/distribute/best-practices/develop/target-sdk',
          'https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage'
        ]
      },
      {
        id: `ps_issue_${Date.now()}_2`,
        title: 'Potentially Excessive Permissions',
        severity: 'medium',
        category: 'Privacy',
        description: 'Based on Play Store metadata, the app may request more permissions than necessary for its stated functionality.',
        recommendation: 'Review app permissions in Play Store listing and ensure they align with core app features. Consider if all permissions are truly necessary.',
        owaspCategory: 'M1: Improper Platform Usage',
        technicalDetails: 'Play Store analysis shows permission requests that may indicate over-privileged access to user data and device features.',
        references: [
          'https://developer.android.com/guide/topics/permissions/overview',
          'https://support.google.com/googleplay/android-developer/answer/9888170'
        ]
      },
      {
        id: `ps_issue_${Date.now()}_3`,
        title: 'Limited Security Analysis from Play Store',
        severity: 'low',
        category: 'Analysis Limitation',
        description: 'Play Store URL analysis provides limited security insights compared to direct APK analysis.',
        recommendation: 'For comprehensive security analysis, download and analyze the APK file directly to get detailed code-level security insights.',
        owaspCategory: 'M1: Improper Platform Usage',
        technicalDetails: 'Play Store analysis relies on publicly available metadata and cannot perform deep code inspection, manifest analysis, or binary security checks.',
        references: [
          'https://owasp.org/www-project-mobile-security-testing-guide/',
          'https://github.com/OWASP/owasp-mstg'
        ]
      }
    ];
    
    const securityScore = calculateSecurityScore(issues);
    const owaspCoverage = generateOwaspCoverage(issues);
    const analysisTime = Math.round((Date.now() - startTime) / 1000);
    
    return {
      id: `playstore_${Date.now()}`,
      appName,
      packageName,
      version: 'Unknown',
      securityScore,
      issues,
      analysisDate: new Date().toISOString(),
      analysisTime,
      owaspCoverage,
      permissions: ['Based on Play Store listing - detailed analysis requires APK'],
      activities: ['Play Store metadata analysis - limited information'],
      services: ['Play Store metadata analysis - limited information'],
      receivers: ['Play Store metadata analysis - limited information'],
      targetSdkVersion: 28, // Assumed older version for demo
      certificates: []
    };
    
  } catch (error) {
    console.error('Play Store analysis error:', error);
    throw new Error(`Failed to analyze Play Store app: ${error.message}`);
  }
}

function calculateSecurityScore(issues: SecurityIssue[]): number {
  let score = 100;
  
  issues.forEach(issue => {
    switch (issue.severity) {
      case 'critical':
        score -= 25;
        break;
      case 'high':
        score -= 20;
        break;
      case 'medium':
        score -= 10;
        break;
      case 'low':
        score -= 5;
        break;
    }
  });
  
  return Math.max(0, score);
}

function generateOwaspCoverage(issues: SecurityIssue[]) {
  return OWASP_CATEGORIES.map(category => {
    const categoryIssues = issues.filter(issue => issue.owaspCategory === category);
    const highestSeverity = categoryIssues.reduce((highest, issue) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return severityOrder[issue.severity] > severityOrder[highest] ? issue.severity : highest;
    }, 'low' as const);
    
    return {
      category,
      issues: categoryIssues.length,
      severity: highestSeverity
    };
  });
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  // Only allow POST requests
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      }
    });
  }

  try {
    // Parse request body
    const body: AnalysisRequest = await req.json();
    
    // Validate request
    if (!body.type || (body.type !== 'apk' && body.type !== 'playstore')) {
      throw new Error('Invalid analysis type. Must be "apk" or "playstore"');
    }
    
    if (!body.data) {
      throw new Error('Missing data field');
    }
    
    let result: AnalysisResult;
    
    if (body.type === 'apk') {
      if (!body.filename) {
        throw new Error('Filename is required for APK analysis');
      }
      
      // Validate base64 data
      try {
        atob(body.data);
      } catch {
        throw new Error('Invalid base64 APK data');
      }
      
      result = await analyzeAPK(body.data, body.filename);
      
    } else if (body.type === 'playstore') {
      // Validate Play Store URL
      if (!body.data.includes('play.google.com/store/apps/details')) {
        throw new Error('Invalid Play Store URL format');
      }
      
      result = await analyzePlayStoreApp(body.data);
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });

  } catch (error) {
    console.error('Analysis error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return new Response(JSON.stringify({ 
      error: errorMessage,
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }
});