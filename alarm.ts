// Alarm notifications. UNTESTED here: needs @react-native-firebase/messaging and @notifee/react-native.
import messaging from '@react-native-firebase/messaging';
import notifee, { AndroidImportance, AndroidCategory } from '@notifee/react-native';
import type { GuardianClient } from './guardianClient';

export const ALARM_CHANNEL = 'security-alarm';

export async function setupAlarm(client: GuardianClient) {
  await messaging().requestPermission();
  await notifee.createChannel({
    id: ALARM_CHANNEL, name: 'إنذارات أمنية', importance: AndroidImportance.HIGH,
    sound: 'alarm', vibration: true, vibrationPattern: [300, 500, 300, 500], bypassDnd: true,
  });
  await client.registerDevice(await messaging().getToken());
  messaging().onTokenRefresh((t) => void client.registerDevice(t));
}

async function showAlarm(m: { data?: Record<string, string>; notification?: { title?: string; body?: string } }) {
  if (m.data?.type !== 'security_alarm') return;
  await notifee.displayNotification({
    title: m.notification?.title ?? 'إنذار أمني', body: m.notification?.body, data: m.data,
    android: {
      channelId: ALARM_CHANNEL, category: AndroidCategory.ALARM, importance: AndroidImportance.HIGH,
      loopSound: true, ongoing: true, pressAction: { id: 'default' }, fullScreenAction: { id: 'default' },
    },
    ios: { sound: 'alarm.caf', interruptionLevel: 'timeSensitive' }, // 'critical' needs Apple's entitlement
  });
}

// Call once at app start (index.js) so alarms work in foreground and background.
export function registerAlarmHandlers() {
  messaging().onMessage(showAlarm);
  messaging().setBackgroundMessageHandler(showAlarm);
}
