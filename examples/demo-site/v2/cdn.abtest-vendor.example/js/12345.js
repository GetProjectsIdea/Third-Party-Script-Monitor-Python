/* A/B testing vendor snippet (demo). Changes whenever the site owner edits an experiment. */
window.abtest = window.abtest || { project: 12345, experiments: [] };
window.abtest.experiments.push({ id: 'hero-colour', variant: 'B' });
/* Project JavaScript added later (harmless DEMO only: it never runs, the monitor only reads it) */
window.abtest.experiments.push({ id: 'checkout-banner', variant: 'A' });
var demoLoaderUrl = 'https://stats-collector.example/t.js';
var demoLabel = atob('ZGVtbw==');
