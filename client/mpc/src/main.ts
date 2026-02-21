import App from './App';

const hostBtn = document.getElementById('host-btn') as HTMLButtonElement;
const joinCodeInput = document.getElementById(
  'join-code-input',
) as HTMLInputElement;
const joinBtn = document.getElementById('join-btn') as HTMLButtonElement;
const joinSpinner = document.getElementById('join-spinner') as HTMLDivElement;
const joinSubmitContainer = document.getElementById(
  'join-submit-container',
) as HTMLDivElement;
const joinSubmitBtn = document.getElementById(
  'join-submit-btn',
) as HTMLButtonElement;
const numberInput = document.getElementById('number-input') as HTMLInputElement;
const submitNumberBtn = document.getElementById(
  'submit-number-btn',
) as HTMLButtonElement;

const step1 = document.getElementById('step-1') as HTMLDivElement;
const step2Host = document.getElementById('step-2-host') as HTMLDivElement;
const step2Join = document.getElementById('step-2-join') as HTMLDivElement;
const step3 = document.getElementById('step-3') as HTMLDivElement;
const step4 = document.getElementById('step-4') as HTMLDivElement;
const step5 = document.getElementById('step-5') as HTMLDivElement;

const progressText = step4.querySelector('p') as HTMLParagraphElement;
const hostCodeElement = document.getElementById('host-code') as HTMLDivElement;
const resultValueElement = document.getElementById(
  'result-value',
) as HTMLSpanElement;

let myNumber: number | null = null;

const app = new App();

async function handleHost() {
  const code = app.generateJoiningCode();
  hostCodeElement.textContent = code;

  step1.classList.add('hidden');
  step2Host.classList.remove('hidden');

  await app.connect(code, 'alice');

  step2Host.classList.add('hidden');
  step3.classList.remove('hidden');
}

async function handleJoin() {
  step1.classList.add('hidden');
  step2Join.classList.remove('hidden');
}

async function handleJoinSubmit() {
  const joinCodeInput = document.getElementById(
    'join-code-input',
  ) as HTMLInputElement;
  const code = joinCodeInput.value;

  joinSpinner.classList.remove('hidden');
  joinSubmitContainer.classList.add('hidden');

  await app.connect(code, 'bob');

  step2Join.classList.add('hidden');
  step3.classList.remove('hidden');
}

async function handleSubmitNumber() {
  const numberInput = document.getElementById(
    'number-input',
  ) as HTMLInputElement;
  myNumber = parseInt(numberInput.value, 10);

  if (myNumber === null || isNaN(myNumber)) {
    // eslint-disable-next-line no-alert
    alert('Please enter a valid number.');
    return;
  }

  step3.classList.add('hidden');
  step4.classList.remove('hidden');

  const { result, myValue } = await app.mpcLargest(myNumber, progress => {
    const percentage = Math.floor(progress * 100);

    // This allows it to start showing % when the MPC is actually started.
    if (percentage > 1) {
      progressText.innerText = `${percentage}%`;
    }
  });

  // 根据比较结果执行不同的逻辑
  if (result === 'smaller') {
    // 如果自己的数字更小，发送给对方并将本地数字设为0
    app.sendNumber(myValue);
    myNumber = 0;
    step4.classList.add('hidden');
    step5.classList.remove('hidden');
    resultValueElement.textContent = `Your order amount: 0.`;
  } else if (result === 'larger') {
    // 如果自己的数字更大，等待接收对方的数字，然后计算差值
    progressText.innerText = 'Waiting for the other party\'s number...';
    const otherNumber = await app.receiveNumber();
    const difference = myValue - otherNumber;
    step4.classList.add('hidden');
    step5.classList.remove('hidden');
    resultValueElement.textContent = `Your order amount: ${difference} `;
  } else {
    // 相等的情况
    step4.classList.add('hidden');
    step5.classList.remove('hidden');
    resultValueElement.textContent = `Your order amount: 0.`;
  }
}

hostBtn.addEventListener('click', handleHost);
joinBtn.addEventListener('click', handleJoin);
submitNumberBtn.addEventListener('click', handleSubmitNumber);
joinSubmitBtn.addEventListener('click', handleJoinSubmit);

joinCodeInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    handleJoinSubmit();
  }
});

numberInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    handleSubmitNumber();
  }
});
