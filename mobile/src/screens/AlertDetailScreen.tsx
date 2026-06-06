import React, { useEffect, useState } from 'react';
import {
  View, Text, ScrollView, TouchableOpacity, Linking,
  StyleSheet, ActivityIndicator,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RouteProp } from '@react-navigation/native';
import { api, XaiChain } from '../services/api';
import { RootStackParamList } from '../../App';

type Props = {
  navigation: NativeStackNavigationProp<RootStackParamList, 'AlertDetail'>;
  route:      RouteProp<RootStackParamList, 'AlertDetail'>;
};

const VERDICT_COLOR = { BLOCK: '#ef4444', FLAG: '#f59e0b', PASS: '#10b981', SKIP: '#475569' } as const;

export default function AlertDetailScreen({ route }: Props) {
  const { alert } = route.params;
  const [chain,   setChain]   = useState<XaiChain | null>(null);
  const [loading, setLoading] = useState(true);
  const [dashUrl, setDashUrl] = useState('https://dash.shadow-warden-ai.com');

  useEffect(() => {
    AsyncStorage.getItem('warden_url').then(u => {
      if (u) setDashUrl(u.replace('api.', 'dash.'));
    });
    api.getXaiChain(alert.request_id)
      .then(setChain)
      .catch(() => setChain(null))
      .finally(() => setLoading(false));
  }, [alert.request_id]);

  const openDashboard = () =>
    Linking.openURL(`${dashUrl}/events/${alert.request_id}`);

  return (
    <ScrollView style={s.root} contentContainerStyle={{ padding: 16, paddingBottom: 40 }}>

      {/* Verdict banner */}
      <View style={[s.banner, { borderColor: alert.risk_level === 'block' ? '#ef4444' : '#f97316' }]}>
        <Text style={s.bannerRisk}>{alert.risk_level.toUpperCase()}</Text>
        <Text style={s.bannerTime}>{new Date(alert.ts).toLocaleString()}</Text>
      </View>

      {/* Metadata */}
      <View style={s.section}>
        {[
          ['Request ID',  alert.request_id],
          ['Latency',     `${alert.elapsed_ms} ms`],
          ['Tenant',      alert.tenant_id],
          ['Secrets',     String(alert.secrets_found?.length ?? 0)],
        ].map(([label, value]) => (
          <View key={label} style={s.metaRow}>
            <Text style={s.metaLabel}>{label}</Text>
            <Text style={s.metaValue} selectable>{value}</Text>
          </View>
        ))}
      </View>

      {/* Flags */}
      {alert.flags.length > 0 && (
        <View style={s.section}>
          <Text style={s.sectionTitle}>Semantic Flags</Text>
          {alert.flags.map(f => (
            <View key={f} style={s.flagRow}>
              <Text style={s.flagText}>⚡ {f}</Text>
            </View>
          ))}
        </View>
      )}

      {/* XAI Chain */}
      <View style={s.section}>
        <Text style={s.sectionTitle}>Pipeline Stages</Text>
        {loading
          ? <ActivityIndicator color="#ef4444" style={{ marginVertical: 16 }} />
          : chain
            ? chain.stages.map(st => (
                <View key={st.stage} style={s.stageRow}>
                  <View style={[s.stageDot, { backgroundColor: st.color ?? '#475569' }]} />
                  <Text style={s.stageName}>{st.stage}</Text>
                  <Text style={[s.stageVerdict, { color: VERDICT_COLOR[st.verdict as keyof typeof VERDICT_COLOR] ?? '#94a3b8' }]}>
                    {st.verdict}
                  </Text>
                  {st.score > 0 && (
                    <Text style={s.stageScore}>{(st.score * 100).toFixed(0)}%</Text>
                  )}
                </View>
              ))
            : <Text style={s.noXai}>XAI chain unavailable</Text>
        }
      </View>

      {/* Counterfactuals */}
      {chain?.counterfactuals?.length ? (
        <View style={s.section}>
          <Text style={s.sectionTitle}>Remediation</Text>
          {chain.counterfactuals.map((c, i) => (
            <View key={i} style={s.cfRow}>
              <Text style={s.cfStage}>{c.stage}</Text>
              <Text style={s.cfAction}>{c.action}</Text>
            </View>
          ))}
        </View>
      ) : null}

      {/* CTA */}
      <TouchableOpacity style={s.btn} onPress={openDashboard}>
        <Text style={s.btnText}>View Full XAI Report ↗</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  root:          { flex: 1, backgroundColor: '#080e1a' },
  banner:        { backgroundColor: 'rgba(239,68,68,0.1)', borderRadius: 14, padding: 16, marginBottom: 16, borderWidth: 1, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  bannerRisk:    { color: '#ef4444', fontSize: 18, fontWeight: '900' },
  bannerTime:    { color: '#64748b', fontSize: 12 },
  section:       { backgroundColor: '#0f172a', borderRadius: 14, padding: 14, marginBottom: 12, borderWidth: 1, borderColor: 'rgba(255,255,255,0.07)' },
  sectionTitle:  { color: '#94a3b8', fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 },
  metaRow:       { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 },
  metaLabel:     { color: '#64748b', fontSize: 12 },
  metaValue:     { color: '#f1f5f9', fontSize: 12, fontFamily: 'monospace', maxWidth: '65%', textAlign: 'right' },
  flagRow:       { paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.04)' },
  flagText:      { color: '#f59e0b', fontSize: 13 },
  stageRow:      { flexDirection: 'row', alignItems: 'center', paddingVertical: 7, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.04)' },
  stageDot:      { width: 8, height: 8, borderRadius: 4, marginRight: 10 },
  stageName:     { color: '#94a3b8', fontSize: 12, flex: 1 },
  stageVerdict:  { fontSize: 11, fontWeight: '700', marginRight: 8 },
  stageScore:    { color: '#475569', fontSize: 10, fontFamily: 'monospace' },
  noXai:         { color: '#475569', fontSize: 13, textAlign: 'center', paddingVertical: 12 },
  cfRow:         { marginBottom: 10 },
  cfStage:       { color: '#64748b', fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 0.5 },
  cfAction:      { color: '#f1f5f9', fontSize: 13, marginTop: 2 },
  btn:           { backgroundColor: '#ef4444', borderRadius: 14, paddingVertical: 15, alignItems: 'center', marginTop: 8, shadowColor: '#ef4444', shadowOpacity: 0.35, shadowRadius: 12, shadowOffset: { width: 0, height: 4 } },
  btnText:       { color: '#fff', fontSize: 15, fontWeight: '700' },
});
