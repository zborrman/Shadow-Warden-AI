import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, Alert, ActivityIndicator, KeyboardAvoidingView, Platform,
} from 'react-native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { api } from '../services/api';
import { registerWithGateway } from '../services/pushService';
import { RootStackParamList } from '../../App';

type Props = { navigation: NativeStackNavigationProp<RootStackParamList, 'Login'> };

export default function LoginScreen({ navigation }: Props) {
  const [url,    setUrl]    = useState('https://api.shadow-warden-ai.com');
  const [key,    setKey]    = useState('');
  const [tenant, setTenant] = useState('default');
  const [loading, setLoading] = useState(false);

  async function connect() {
    if (!key.trim()) { Alert.alert('API key required'); return; }
    setLoading(true);
    try {
      await api.saveConfig(url.trim(), key.trim());
      const health = await api.getHealth();
      if (health.status !== 'ok' && health.status !== 'degraded') throw new Error('Gateway unhealthy');
      await registerWithGateway(tenant.trim() || 'default');
      navigation.replace('Alerts');
    } catch (e: any) {
      Alert.alert('Connection failed', e.message ?? String(e));
      setLoading(false);
    }
  }

  return (
    <KeyboardAvoidingView style={s.root} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <View style={s.card}>
        <View style={s.logo}><Text style={s.logoText}>🛡️</Text></View>
        <Text style={s.title}>Shadow Warden</Text>
        <Text style={s.sub}>Mobile SOC</Text>

        <Text style={s.label}>Gateway URL</Text>
        <TextInput
          style={s.input}
          value={url}
          onChangeText={setUrl}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          placeholder="https://api.shadow-warden-ai.com"
          placeholderTextColor="#475569"
        />

        <Text style={s.label}>API Key</Text>
        <TextInput
          style={s.input}
          value={key}
          onChangeText={setKey}
          secureTextEntry
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="sk-warden-…"
          placeholderTextColor="#475569"
        />

        <Text style={s.label}>Tenant ID</Text>
        <TextInput
          style={s.input}
          value={tenant}
          onChangeText={setTenant}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="default"
          placeholderTextColor="#475569"
        />

        <TouchableOpacity style={[s.btn, loading && s.btnDim]} onPress={connect} disabled={loading}>
          {loading
            ? <ActivityIndicator color="#fff" />
            : <Text style={s.btnText}>Connect & Enable Push Alerts</Text>
          }
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const s = StyleSheet.create({
  root:    { flex: 1, backgroundColor: '#080e1a', justifyContent: 'center', padding: 24 },
  card:    { backgroundColor: '#0f172a', borderRadius: 20, padding: 24, borderWidth: 1, borderColor: 'rgba(255,255,255,0.08)' },
  logo:    { alignItems: 'center', marginBottom: 8 },
  logoText:{ fontSize: 40 },
  title:   { color: '#f1f5f9', fontSize: 22, fontWeight: '800', textAlign: 'center' },
  sub:     { color: '#ef4444', fontSize: 13, fontWeight: '700', textAlign: 'center', marginBottom: 24, letterSpacing: 2 },
  label:   { color: '#94a3b8', fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 },
  input:   { backgroundColor: '#1e293b', color: '#f1f5f9', borderRadius: 10, paddingHorizontal: 14, paddingVertical: 11, fontSize: 14, marginBottom: 16, borderWidth: 1, borderColor: 'rgba(255,255,255,0.08)' },
  btn:     { backgroundColor: '#ef4444', borderRadius: 12, paddingVertical: 15, alignItems: 'center', marginTop: 8 },
  btnDim:  { opacity: 0.6 },
  btnText: { color: '#fff', fontSize: 15, fontWeight: '700' },
});
