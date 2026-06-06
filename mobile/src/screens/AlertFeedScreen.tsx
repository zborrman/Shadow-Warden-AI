import React, { useCallback, useEffect, useState } from 'react';
import {
  View, Text, FlatList, TouchableOpacity, RefreshControl,
  StyleSheet, ActivityIndicator,
} from 'react-native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { api, AlertEntry } from '../services/api';
import { getStoredAlerts, PushAlert } from '../services/pushService';
import { RootStackParamList } from '../../App';

type Props = { navigation: NativeStackNavigationProp<RootStackParamList, 'Alerts'> };

const RISK_COLOR = { block: '#ef4444', high: '#ef4444', medium: '#f59e0b', low: '#10b981' } as const;
const RISK_ICON  = { block: '🚨', high: '🔴', medium: '🟡', low: '🟢' } as const;

function RiskBadge({ level }: { level: string }) {
  const color = RISK_COLOR[level as keyof typeof RISK_COLOR] ?? '#94a3b8';
  const icon  = RISK_ICON [level as keyof typeof RISK_ICON]  ?? '⚪';
  return (
    <View style={[s.badge, { backgroundColor: color + '20', borderColor: color + '40' }]}>
      <Text style={[s.badgeText, { color }]}>{icon} {level.toUpperCase()}</Text>
    </View>
  );
}

export default function AlertFeedScreen({ navigation }: Props) {
  const [alerts,      setAlerts]      = useState<AlertEntry[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [error,       setError]       = useState('');

  const load = useCallback(async (isRefresh = false) => {
    if (!isRefresh) setLoading(true);
    setError('');
    try {
      const data = await api.getAlerts(100, 'high');
      setAlerts(data);
    } catch (e: any) {
      setError(e.message ?? 'Failed to load alerts');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    api.loadConfig().then(() => load());
    const timer = setInterval(() => load(), 30_000);
    return () => clearInterval(timer);
  }, [load]);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color="#ef4444" />
        <Text style={s.loadText}>Loading alerts…</Text>
      </View>
    );
  }

  return (
    <View style={s.root}>
      {error ? (
        <View style={s.errorBar}>
          <Text style={s.errorText}>⚠ {error}</Text>
        </View>
      ) : null}
      <FlatList
        data={alerts}
        keyExtractor={i => i.request_id}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => { setRefreshing(true); load(true); }}
            tintColor="#ef4444"
          />
        }
        ListEmptyComponent={
          <View style={s.empty}>
            <Text style={s.emptyIcon}>✅</Text>
            <Text style={s.emptyText}>No HIGH/BLOCK alerts</Text>
            <Text style={s.emptySub}>Pull to refresh</Text>
          </View>
        }
        contentContainerStyle={alerts.length === 0 ? { flex: 1 } : { padding: 16 }}
        ItemSeparatorComponent={() => <View style={{ height: 10 }} />}
        renderItem={({ item }) => (
          <TouchableOpacity
            style={s.card}
            onPress={() => navigation.navigate('AlertDetail', { alert: item })}
            activeOpacity={0.75}
          >
            <View style={s.cardRow}>
              <RiskBadge level={item.risk_level} />
              <Text style={s.ts}>{new Date(item.ts).toLocaleTimeString()}</Text>
            </View>
            <Text style={s.flags} numberOfLines={1}>
              {item.flags.length > 0 ? item.flags.join(' · ') : 'No flags'}
            </Text>
            <Text style={s.rid} numberOfLines={1}>
              ID: {item.request_id.slice(0, 16)}…
            </Text>
          </TouchableOpacity>
        )}
      />
    </View>
  );
}

const s = StyleSheet.create({
  root:      { flex: 1, backgroundColor: '#080e1a' },
  center:    { flex: 1, alignItems: 'center', justifyContent: 'center', backgroundColor: '#080e1a' },
  loadText:  { color: '#64748b', marginTop: 12, fontSize: 13 },
  errorBar:  { backgroundColor: 'rgba(239,68,68,0.12)', padding: 12 },
  errorText: { color: '#ef4444', fontSize: 13, textAlign: 'center' },
  empty:     { flex: 1, alignItems: 'center', justifyContent: 'center' },
  emptyIcon: { fontSize: 48, marginBottom: 12 },
  emptyText: { color: '#f1f5f9', fontSize: 17, fontWeight: '700' },
  emptySub:  { color: '#64748b', fontSize: 13, marginTop: 6 },
  card:      { backgroundColor: '#0f172a', borderRadius: 14, padding: 14, borderWidth: 1, borderColor: 'rgba(255,255,255,0.07)' },
  cardRow:   { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 },
  badge:     { borderRadius: 8, paddingHorizontal: 10, paddingVertical: 4, borderWidth: 1 },
  badgeText: { fontSize: 11, fontWeight: '700' },
  ts:        { color: '#64748b', fontSize: 11, fontFamily: 'monospace' },
  flags:     { color: '#94a3b8', fontSize: 12, marginBottom: 4 },
  rid:       { color: '#334155', fontSize: 10, fontFamily: 'monospace' },
});
