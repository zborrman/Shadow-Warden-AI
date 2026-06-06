/**
 * mobile/App.tsx
 * ──────────────
 * Shadow Warden Mobile SOC — root component.
 *
 * Navigation stack:
 *   Login → Alerts → AlertDetail
 *             ↕
 *           Settings (header button)
 *
 * Push notifications are registered on app start and handled here.
 * Foreground alerts trigger a badge on the Alerts tab header.
 */
import React, { useEffect, useRef, useState } from 'react';
import { Alert, AppState, StatusBar, Text, TouchableOpacity, View } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { NavigationContainer } from '@react-navigation/native';
import {
  NativeStackNavigationProp,
  createNativeStackNavigator,
} from '@react-navigation/native-stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import LoginScreen       from './src/screens/LoginScreen';
import AlertFeedScreen   from './src/screens/AlertFeedScreen';
import AlertDetailScreen from './src/screens/AlertDetailScreen';
import SettingsScreen    from './src/screens/SettingsScreen';
import { AlertEntry }    from './src/services/api';
import {
  PushAlert,
  requestPermission,
  setupPushHandlers,
  storeAlert,
} from './src/services/pushService';

export type RootStackParamList = {
  Login:       undefined;
  Alerts:      undefined;
  AlertDetail: { alert: AlertEntry };
  Settings:    undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export default function App() {
  const [initialRoute, setInitialRoute] = useState<keyof RootStackParamList | null>(null);
  const [newAlerts,    setNewAlerts]    = useState(0);

  useEffect(() => {
    // Determine initial screen based on stored credentials
    AsyncStorage.getItem('warden_api_key').then(key => {
      setInitialRoute(key ? 'Alerts' : 'Login');
    });

    // Request notification permissions
    requestPermission().catch(() => {});

    // Wire up push handlers
    const unsub = setupPushHandlers((alert: PushAlert) => {
      setNewAlerts(n => n + 1);
    });

    return unsub;
  }, []);

  if (!initialRoute) return null;

  return (
    <SafeAreaProvider>
      <StatusBar barStyle="light-content" backgroundColor="#080e1a" />
      <NavigationContainer>
        <Stack.Navigator
          initialRouteName={initialRoute}
          screenOptions={{
            headerStyle:      { backgroundColor: '#0f172a' },
            headerTintColor:  '#f1f5f9',
            headerTitleStyle: { fontWeight: '700', fontSize: 16 },
            contentStyle:     { backgroundColor: '#080e1a' },
          }}
        >
          <Stack.Screen
            name="Login"
            component={LoginScreen}
            options={{ headerShown: false }}
          />
          <Stack.Screen
            name="Alerts"
            component={AlertFeedScreen}
            options={({ navigation }) => ({
              title: 'SOC Alerts',
              headerRight: () => (
                <TouchableOpacity onPress={() => { setNewAlerts(0); navigation.navigate('Settings'); }}>
                  <Text style={{ color: '#ef4444', fontSize: 13, fontWeight: '700' }}>
                    ⚙ Settings{newAlerts > 0 ? ` · ${newAlerts} new` : ''}
                  </Text>
                </TouchableOpacity>
              ),
            })}
          />
          <Stack.Screen
            name="AlertDetail"
            options={{ title: 'Alert Detail' }}
            component={AlertDetailScreen}
          />
          <Stack.Screen
            name="Settings"
            component={SettingsScreen}
            options={{ title: 'Settings' }}
          />
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
