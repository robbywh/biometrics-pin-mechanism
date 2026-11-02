import React from 'react';
import { Stack } from 'expo-router';

export default function AppLayout() {
  return <Stack screenOptions={{ headerStyle: { backgroundColor: '#0B1020' }, headerTintColor: '#F4F6FB', contentStyle: { backgroundColor: '#0B1020' } }} />;
}
