import App from './App';

// DOM 元素
const hostBtn = document.getElementById('host-btn') as HTMLButtonElement;
const joinBtn = document.getElementById('join-btn') as HTMLButtonElement;
const joinCodeInput = document.getElementById('join-code-input') as HTMLInputElement;
const joinSubmitBtn = document.getElementById('join-submit-btn') as HTMLButtonElement;
const joinSpinner = document.getElementById('join-spinner') as HTMLDivElement;
const joinSubmitContainer = document.getElementById('join-submit-container') as HTMLDivElement;

const connectionSection = document.getElementById('connection-section') as HTMLDivElement;
const connectionStatus = document.getElementById('connection-status') as HTMLDivElement;
const connectionText = document.getElementById('connection-text') as HTMLSpanElement;

const connectionModal = document.getElementById('connection-modal') as HTMLDivElement;
const hostModal = document.getElementById('host-modal') as HTMLDivElement;
const joinModal = document.getElementById('join-modal') as HTMLDivElement;
const hostCodeElement = document.getElementById('host-code') as HTMLDivElement;

const buyTypeBtn = document.getElementById('buy-type-btn') as HTMLButtonElement;
const sellTypeBtn = document.getElementById('sell-type-btn') as HTMLButtonElement;
const amountInput = document.getElementById('amount-input') as HTMLInputElement;
const priceInput = document.getElementById('price-input') as HTMLInputElement;
const totalAmount = document.getElementById('total-amount') as HTMLSpanElement;
const amountHint = document.getElementById('amount-hint') as HTMLSpanElement;
const submitOrderBtn = document.getElementById('submit-order-btn') as HTMLButtonElement;

const orderList = document.getElementById('order-list') as HTMLDivElement;
const tabButtons = document.querySelectorAll('.tab-btn') as NodeListOf<HTMLButtonElement>;

const processingOverlay = document.getElementById('processing-overlay') as HTMLDivElement;
const progressText = document.getElementById('progress-text') as HTMLParagraphElement;

// 状态
let currentOrderType: 'buy' | 'sell' = 'buy';
let isConnected = false;
const orders: Order[] = [];

// 订单接口
interface Order {
  id: string;
  type: 'buy' | 'sell';
  amount: number;
  price: number;
  total: number;
  p2pHash: string;
  status: 'pending' | 'completed';
  orderAmount: number; // MPC 计算后的订单金额
}

const app = new App();

// 生成 P2P Hash
function generateP2PHash(): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  const hash = `${timestamp}-${random}`;
  // 简单的 hash 生成（实际应用中可以使用 crypto API）
  return btoa(hash).substring(0, 16);
}

// 计算总金额
function updateTotal() {
  const amount = parseFloat(amountInput.value) || 0;
  const price = parseFloat(priceInput.value) || 0;
  const total = amount * price;
  totalAmount.textContent = `${total.toFixed(2)} USDT`;
  
  // 启用/禁用提交按钮
  submitOrderBtn.disabled = amount <= 0 || price <= 0 || !isConnected;
}

// 切换订单类型
function setOrderType(type: 'buy' | 'sell') {
  currentOrderType = type;
  buyTypeBtn.classList.toggle('active', type === 'buy');
  sellTypeBtn.classList.toggle('active', type === 'sell');
  amountHint.textContent = type === 'buy' ? 'ETH' : 'USDT';
}

// 添加订单到列表
function addOrderToBook(order: Order) {
  orders.push(order);
  renderOrders();
}

// 更新订单状态
function updateOrderStatus(orderId: string, status: 'pending' | 'completed', orderAmount?: number) {
  const order = orders.find(o => o.id === orderId);
  if (order) {
    order.status = status;
    if (orderAmount !== undefined) {
      order.orderAmount = orderAmount;
    }
    renderOrders();
  }
}

// 渲染订单列表
function renderOrders(filter?: 'all' | 'buy' | 'sell') {
  const filteredOrders = filter === 'all' || !filter
    ? orders
    : orders.filter(o => o.type === filter);

  if (filteredOrders.length === 0) {
    orderList.innerHTML = '<div class="empty-state">No orders yet</div>';
    return;
  }

  orderList.innerHTML = filteredOrders.map(order => `
    <div class="order-row">
      <div class="col-type ${order.type}">${order.type === 'buy' ? 'Buy' : 'Sell'}</div>
      <div class="col-amount">${order.amount.toFixed(4)}</div>
      <div class="col-price">${order.price.toFixed(2)}</div>
      <div class="col-total">${order.total.toFixed(2)}</div>
      <div class="col-hash" title="${order.p2pHash}">${order.p2pHash}</div>
      <div class="col-status">
        <span class="status-${order.status}">${order.status === 'pending' ? 'Processing' : 'Completed'}</span>
        ${order.orderAmount !== undefined ? `<br><small>Amount: ${order.orderAmount}</small>` : ''}
      </div>
    </div>
  `).join('');
}

// 连接处理
async function handleHost() {
  const code = app.generateJoiningCode();
  hostCodeElement.textContent = code;
  
  connectionModal.classList.remove('hidden');
  hostModal.classList.remove('hidden');
  joinModal.classList.add('hidden');

  await app.connect(code, 'alice');

  connectionModal.classList.add('hidden');
  connectionSection.classList.add('hidden');
  connectionStatus.classList.remove('hidden');
  connectionText.textContent = 'Connected';
  isConnected = true;
  updateTotal();
}

async function handleJoin() {
  connectionModal.classList.remove('hidden');
  joinModal.classList.remove('hidden');
  hostModal.classList.add('hidden');
}

async function handleJoinSubmit() {
  const code = joinCodeInput.value.trim();
  if (!code) {
    alert('Please enter a connection code.');
    return;
  }

  joinSpinner.classList.remove('hidden');
  joinSubmitContainer.classList.add('hidden');

  try {
    await app.connect(code, 'bob');
    
    connectionModal.classList.add('hidden');
    connectionSection.classList.add('hidden');
    connectionStatus.classList.remove('hidden');
    connectionText.textContent = 'Connected';
    isConnected = true;
    updateTotal();
  } catch (error) {
    joinSpinner.classList.add('hidden');
    joinSubmitContainer.classList.remove('hidden');
    alert('Failed to connect. Please check the code and try again.');
  }
}

// 提交订单
async function handleSubmitOrder() {
  const amount = parseFloat(amountInput.value);
  const price = parseFloat(priceInput.value);

  if (isNaN(amount) || amount <= 0) {
    alert('Please enter a valid amount.');
    return;
  }

  if (isNaN(price) || price <= 0) {
    alert('Please enter a valid price.');
    return;
  }

  const total = amount * price;
  const orderId = `order-${Date.now()}`;
  const p2pHash = generateP2PHash();

  // 创建订单
  const order: Order = {
    id: orderId,
    type: currentOrderType,
    amount,
    price,
    total,
    p2pHash,
    status: 'pending',
    orderAmount: 0,
  };

  // 添加到订单簿
  addOrderToBook(order);

  // 清空表单
  amountInput.value = '';
  priceInput.value = '';
  updateTotal();

  // 显示处理中
  processingOverlay.classList.remove('hidden');
  progressText.innerText = 'Processing order...';

  // 计算订单金额（使用 total 作为 MPC 输入）
  const orderValue = Math.floor(total);

  try {
    const { result, myValue } = await app.mpcLargest(orderValue, progress => {
      const percentage = Math.floor(progress * 100);
      if (percentage > 1) {
        progressText.innerText = `Processing order... ${percentage}%`;
      }
    });

    let finalAmount = 0;

    // 根据比较结果执行不同的逻辑
    if (result === 'smaller') {
      // 如果自己的数字更小，发送给对方并将本地数字设为0
      app.sendNumber(myValue);
      finalAmount = 0;
    } else if (result === 'larger') {
      // 如果自己的数字更大，等待接收对方的数字，然后计算差值
      progressText.innerText = 'Waiting for the other party\'s order...';
      const otherNumber = await app.receiveNumber();
      finalAmount = myValue - otherNumber;
    } else {
      // 相等的情况
      finalAmount = 0;
    }

    // 更新订单状态
    updateOrderStatus(orderId, 'completed', finalAmount);

    // 隐藏处理中
    processingOverlay.classList.add('hidden');
  } catch (error) {
    console.error('Order processing error:', error);
    alert('Failed to process order. Please try again.');
    processingOverlay.classList.add('hidden');
    // 移除失败的订单
    const index = orders.findIndex(o => o.id === orderId);
    if (index > -1) {
      orders.splice(index, 1);
      renderOrders();
    }
  }
}

// 标签切换
tabButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    tabButtons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.getAttribute('data-tab') as 'all' | 'buy' | 'sell';
    renderOrders(tab);
  });
});

// 事件监听
hostBtn.addEventListener('click', handleHost);
joinBtn.addEventListener('click', handleJoin);
joinSubmitBtn.addEventListener('click', handleJoinSubmit);
buyTypeBtn.addEventListener('click', () => setOrderType('buy'));
sellTypeBtn.addEventListener('click', () => setOrderType('sell'));
submitOrderBtn.addEventListener('click', handleSubmitOrder);

amountInput.addEventListener('input', updateTotal);
priceInput.addEventListener('input', updateTotal);

joinCodeInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    handleJoinSubmit();
  }
});

amountInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    priceInput.focus();
  }
});

priceInput.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !submitOrderBtn.disabled) {
    handleSubmitOrder();
  }
});

// 初始化
setOrderType('buy');
renderOrders('all');
