interface AnalysisRequest {
  type: 'apk' | 'playstore';
  data: string;
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

const ANALYZER_API_URL = 'https://j7fsbq0f--apk-analyzer.functions.blink.new';

export async function analyzeAPKFile(file: File): Promise<AnalysisResult> {
  try {
    // Convert file to base64
    const base64Data = await fileToBase64(file);
    
    const request: AnalysisRequest = {
      type: 'apk',
      data: base64Data,
      filename: file.name
    };

    const response = await fetch(ANALYZER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Analysis failed with status ${response.status}`);
    }

    const result: AnalysisResult = await response.json();
    return result;

  } catch (error) {
    console.error('APK analysis error:', error);
    throw new Error(`Failed to analyze APK: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export async function analyzePlayStoreURL(url: string): Promise<AnalysisResult> {
  try {
    // Validate Play Store URL
    if (!url.includes('play.google.com/store/apps/details')) {
      throw new Error('Invalid Play Store URL. Please provide a valid Google Play Store app URL.');
    }

    const request: AnalysisRequest = {
      type: 'playstore',
      data: url
    };

    const response = await fetch(ANALYZER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Analysis failed with status ${response.status}`);
    }

    const result: AnalysisResult = await response.json();
    return result;

  } catch (error) {
    console.error('Play Store analysis error:', error);
    throw new Error(`Failed to analyze Play Store app: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = () => {
      const result = reader.result as string;
      // Remove data URL prefix to get just the base64 data
      const base64Data = result.split(',')[1];
      resolve(base64Data);
    };
    
    reader.onerror = () => {
      reject(new Error('Failed to read file'));
    };
    
    reader.readAsDataURL(file);
  });
}

export function validateAPKFile(file: File): { valid: boolean; error?: string } {
  // Check file extension
  if (!file.name.toLowerCase().endsWith('.apk')) {
    return { valid: false, error: 'File must have .apk extension' };
  }

  // Check file size (limit to 100MB)
  const maxSize = 100 * 1024 * 1024; // 100MB
  if (file.size > maxSize) {
    return { valid: false, error: 'APK file size must be less than 100MB' };
  }

  // Check minimum file size (APK files are typically at least 1KB)
  if (file.size < 1024) {
    return { valid: false, error: 'File appears to be too small to be a valid APK' };
  }

  return { valid: true };
}

export function validatePlayStoreURL(url: string): { valid: boolean; error?: string } {
  try {
    const urlObj = new URL(url);
    
    // Check if it's a Google Play Store URL
    if (!urlObj.hostname.includes('play.google.com')) {
      return { valid: false, error: 'URL must be from play.google.com' };
    }

    // Check if it's an app details page
    if (!urlObj.pathname.includes('/store/apps/details')) {
      return { valid: false, error: 'URL must be an app details page (/store/apps/details)' };
    }

    // Check if it has an app ID parameter
    const appId = urlObj.searchParams.get('id');
    if (!appId) {
      return { valid: false, error: 'URL must contain an app ID parameter (id=...)' };
    }

    // Validate app ID format (basic check)
    if (!/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$/.test(appId)) {
      return { valid: false, error: 'Invalid app ID format' };
    }

    return { valid: true };

  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

export type { AnalysisResult, SecurityIssue };