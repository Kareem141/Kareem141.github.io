import React from 'react';
import { createRoot } from 'react-dom/client';
import LiquidEther from './components/LiquidEther.jsx';

const mount = document.getElementById('liquid-ether-root');

if (mount) {
  createRoot(mount).render(
    <LiquidEther
      className="liquid-ether-background"
      colors={['#5227FF', '#FF9FFC', '#B497CF']}
      mouseForce={20}
      cursorSize={100}
      iterationsViscous={0}
      iterationsPoisson={12}
      resolution={0.3}
      isBounce={false}
      autoDemo
      autoSpeed={0.5}
      autoIntensity={2.2}
      takeoverDuration={0.25}
      autoResumeDelay={3000}
      autoRampDuration={0.6}
      lightMode={false}
    />
  );
}