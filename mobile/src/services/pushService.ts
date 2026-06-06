/**
 * mobile/src/services/pushService.ts
 * ─────────────────────────────────────
 * Firebase Cloud Messaging integration.
 * Requests notification permissions, retrieves the FCM token,
 * registers it with the Shadow Warden gateway, and handles
 * foreground / background / quit-state messages.
 */
import messaging, { FirebaseMessagingTypes } from '@react-native-firebase/messaging';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { api } from './api';

export type PushAlert = {
  requestId:   string;
  riskLevel:   string;
  attackType:  string;
  tenantId:    string;
  ruleSummary: string;
  receivedAt:  string;
};

const ALERTS_KEY = 'push_alerts';
const MAX_STORED  = 100;

export async function requestPermission(): Promise<boolean> {
  const status = await messaging().requestPermission();
  return (
    status === messaging.AuthorizationStatus.AUTHORIZED ||
    status === messaging.AuthorizationStatus.PROVISIONAL
  );
}

export async function getFCMToken(): Promise<string | null> {
  try {
    if (!messaging().isDeviceRegisteredForRemoteMessages) {
      await messaging().registerDeviceForRemoteMessages();
    }
    return await messaging().getToken();
  } catch {
    return null;
  }
}

export async function registerWithGateway(tenantId = 'default'): Promise<void> {
  const token = await getFCMToken();
  if (!token) return;
  const cached = await AsyncStorage.getItem('fcm_token');
  if (cached === token) return; // already registered
  await api.registerPushToken(token, 'android', tenantId); // 'ios' on iOS
  await AsyncStorage.setItem('fcm_token', token);
}

function parseMessage(message: FirebaseMessagingTypes.RemoteMessage): PushAlert | null {
  const d = message.data;
  if (!d?.risk_level) return null;
  return {
    requestId:   String(d.request_id ?? ''),
    riskLevel:   String(d.risk_level),
    attackType:  String(d.attack_type ?? 'unknown'),
    tenantId:    String(d.tenant_id ?? 'default'),
    ruleSummary: String(d.rule_summary ?? ''),
    receivedAt:  new Date().toISOString(),
  };
}

export async function storeAlert(alert: PushAlert): Promise<void> {
  const raw  = await AsyncStorage.getItem(ALERTS_KEY);
  const list: PushAlert[] = raw ? JSON.parse(raw) : [];
  list.unshift(alert);
  if (list.length > MAX_STORED) list.splice(MAX_STORED);
  await AsyncStorage.setItem(ALERTS_KEY, JSON.stringify(list));
}

export async function getStoredAlerts(): Promise<PushAlert[]> {
  const raw = await AsyncStorage.getItem(ALERTS_KEY);
  return raw ? JSON.parse(raw) : [];
}

export async function clearAlerts(): Promise<void> {
  await AsyncStorage.removeItem(ALERTS_KEY);
}

/** Call once in App.tsx. Returns an unsubscribe function. */
export function setupPushHandlers(
  onForegroundAlert: (alert: PushAlert) => void,
): () => void {
  // Foreground messages
  const unsubFg = messaging().onMessage(async msg => {
    const alert = parseMessage(msg);
    if (alert) {
      await storeAlert(alert);
      onForegroundAlert(alert);
    }
  });

  // Background / quit — message opened the app
  messaging().onNotificationOpenedApp(async msg => {
    const alert = parseMessage(msg);
    if (alert) await storeAlert(alert);
  });

  // App launched from quit state via notification
  messaging().getInitialNotification().then(async msg => {
    if (msg) {
      const alert = parseMessage(msg);
      if (alert) await storeAlert(alert);
    }
  });

  return unsubFg;
}
