import React, { useEffect, useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, ScrollView,
  StyleSheet, Switch, Alert,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { api } from '../services/api';
import { getFCMToken, clearAlerts } from '../services/pushService';
import { RootStackParamList } from '../../App';

type Props = { navigation: NativeStackNavigationProp<RootStackParamList, 'Settings'> };

export default function SettingsScreen({ navigation }: Props) {
  const [url,     setUrl]     = useState('');
  const [key,     setKey]     = useState('');
  const [tenant,  setTenant]  = useState('default');
  const [token,   setToken]   = useState('');
  const [pushOn,  setPushOn]  = useState(true);

  useEffect(() => {
    AsyncStorage.multiGet(['warden_url', 'warden_api_key', 'warden_tenant', 'push_enabled']).then(pairs => {
      const m = Object.fromEntries(pairs.map(([k, v]) => [k, v ?? '']));
      setUrl(m.warden_url || 'https://api.shadow-warden-ai.com');
      setKey(m.warden_api_key);
      setTenant(m.warden_tenant || 'default');
      setPushOn(m.push_enabled !== 'false');
    });
    getFCMToken().then(t => setToken(t ?? 'Unavailable'));
  }, []);

  async function save() {
    await api.saveConfig(url.trim(), key.trim());
    await AsyncStorage.setItem('warden_tenant',  tenant.trim() || 'default');
    await AsyncStorage.setItem('push_enabled',   String(pushOn));
    Alert.alert('Saved', 'Settings updated.');
  }

  async function logout() {
    await AsyncStorage.multiRemove(['warden_url', 'warden_api_key', 'warden_tenant', 'fcm_token', 'push_alerts']);
    navigation.replace('Login');
  }

  async function wipeAlerts() {
    await clearAlerts();
    Alert.alert('Done', 'Alert history cleared.');
  }

  return (
    <ScrollView style={s.root} contentContainerStyle={{ padding: 16, paddingBottom: 60 }}>

      <Text style={s.sectionTitle}>Connection</Text>
      <View style={s.card}>
        <Text style={s.label}>Gateway URL</Text>
        <TextInput style={s.input} value={url} onChangeText={setUrl} autoCapitalize="none" autoCorrect={false} keyboardType="url" placeholderTextColor="#475569" />
        <Text style={s.label}>API Key</Text>
        <TextInput style={s.input} value={key} onChangeText={setKey} secureTextEntry autoCapitalize="none" autoCorrect={false} placeholderTextColor="#475569" />
        <Text style={s.label}>Tenant ID</Text>
        <TextInput style={s.input} value={tenant} onChangeText={setTenant} autoCapitalize="none" autoCorrect={false} placeholderTextColor="#475569" />
      </View>

      <Text style={s.sectionTitle}>Notifications</Text>
      <View style={s.card}>
        <View style={s.row}>
          <Text style={s.rowLabel}>Push Alerts (HIGH/BLOCK)</Text>
          <Switch value={pushOn} onValueChange={setPushOn} trackColor={{ true: '#ef4444', false: '#1e293b' }} thumbColor="#fff" />
        </View>
        <Text style={s.sub}>FCM Token</Text>
        <Text style={s.mono} selectable numberOfLines={2}>{token}</Text>
      </View>

      <Text style={s.sectionTitle}>Data</Text>
      <View style={s.card}>
        <TouchableOpacity style={s.dangerBtn} onPress={wipeAlerts}>
          <Text style={s.dangerText}>Clear Alert History</Text>
        </TouchableOpacity>
      </View>

      <TouchableOpacity style={s.saveBtn} onPress={save}>
        <Text style={s.saveBtnText}>Save Settings</Text>
      </TouchableOpacity>

      <TouchableOpacity style={s.logoutBtn} onPress={logout}>
        <Text style={s.logoutText}>Sign Out</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  root:         { flex: 1, backgroundColor: '#080e1a' },
  sectionTitle: { color: '#64748b', fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8, marginTop: 20 },
  card:         { backgroundColor: '#0f172a', borderRadius: 14, padding: 14, borderWidth: 1, borderColor: 'rgba(255,255,255,0.07)' },
  label:        { color: '#94a3b8', fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 },
  input:        { backgroundColor: '#1e293b', color: '#f1f5f9', borderRadius: 10, paddingHorizontal: 14, paddingVertical: 11, fontSize: 14, marginBottom: 14, borderWidth: 1, borderColor: 'rgba(255,255,255,0.08)' },
  row:          { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 },
  rowLabel:     { color: '#f1f5f9', fontSize: 14, flex: 1 },
  sub:          { color: '#64748b', fontSize: 11, marginBottom: 6 },
  mono:         { color: '#475569', fontSize: 10, fontFamily: 'monospace' },
  dangerBtn:    { backgroundColor: 'rgba(239,68,68,0.1)', borderRadius: 10, paddingVertical: 12, alignItems: 'center', borderWidth: 1, borderColor: 'rgba(239,68,68,0.2)' },
  dangerText:   { color: '#ef4444', fontSize: 14, fontWeight: '600' },
  saveBtn:      { backgroundColor: '#ef4444', borderRadius: 14, paddingVertical: 15, alignItems: 'center', marginTop: 24 },
  saveBtnText:  { color: '#fff', fontSize: 15, fontWeight: '700' },
  logoutBtn:    { borderRadius: 14, paddingVertical: 15, alignItems: 'center', marginTop: 12, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)' },
  logoutText:   { color: '#64748b', fontSize: 15 },
});
