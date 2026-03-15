const steps = [
  'Scanning trend feeds for high-intent AI-agent niches',
  'Generating landing page + onboarding emails',
  'Provisioning autonomous support + sales agents',
  'Launching A/B pricing experiments',
  'Monitoring conversion and auto-optimizing funnels'
];

const pipeline = document.getElementById('pipeline');
const demoButton = document.getElementById('demoButton');
const startTrial = document.getElementById('startTrial');

document.getElementById('year').textContent = new Date().getFullYear();

function render(statusMap) {
  pipeline.innerHTML = '';
  steps.forEach((step, idx) => {
    const li = document.createElement('li');
    const state = statusMap[idx] || 'waiting';
    li.innerHTML = `<span>${idx + 1}. ${step}</span><span class="badge ${state}">${state.toUpperCase()}</span>`;
    pipeline.appendChild(li);
  });
}

function runDemo() {
  const status = {};
  render(status);

  steps.forEach((_, idx) => {
    setTimeout(() => {
      status[idx] = 'running';
      render(status);

      setTimeout(() => {
        status[idx] = 'done';
        render(status);
      }, 650);
    }, idx * 900);
  });
}

demoButton.addEventListener('click', runDemo);
startTrial.addEventListener('click', () => {
  runDemo();
  alert('✅ Trial activated. Your first autonomous workflow is now deploying.');
});

render({});
