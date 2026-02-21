import { RtcPairSocket } from 'rtc-pair-socket';
import AsyncQueue from './AsyncQueue';
import assert from './assert';
import generateProtocol from './generateProtocol';

export default class App {
  socket?: RtcPairSocket;
  party?: 'alice' | 'bob';
  msgQueue = new AsyncQueue<unknown>();
  numberQueue = new AsyncQueue<unknown>(); // 用于接收数字消息的队列

  generateJoiningCode() {
    // 128 bits of entropy
    return [
      Math.random().toString(36).substring(2, 12),
      Math.random().toString(36).substring(2, 12),
      Math.random().toString(36).substring(2, 7),
    ].join('');
  }

  async connect(code: string, party: 'alice' | 'bob') {
    this.party = party;
    const socket = new RtcPairSocket(code, party);
    this.socket = socket;

    socket.on('message', (msg: unknown) => {
      // 检查是否是数字传输消息
      if (msg instanceof Uint8Array) {
        try {
          const text = new TextDecoder().decode(msg);
          const data = JSON.parse(text);
          if (data.type === 'number') {
            this.numberQueue.push(data.value);
            return; // 不推送到 MPC 消息队列
          }
        } catch (error) {
          // 不是 JSON 消息，继续处理
        }
      }
      
      // Using a message queue instead of passing messages directly to the MPC
      // protocol ensures that we don't miss anything sent before we begin.
      this.msgQueue.push(msg);
    });

    await new Promise<void>((resolve, reject) => {
      socket.on('open', resolve);
      socket.on('error', reject);
    });
  }

  async mpcLargest(
    value: number,
    onProgress?: (progress: number) => void,
  ): Promise<{ result: 'larger' | 'smaller' | 'equal'; myValue: number }> {
    const { party, socket } = this;

    assert(party !== undefined, 'Party must be set');
    assert(socket !== undefined, 'Socket must be set');

    const TOTAL_BYTES = 247331;
    let currentBytes = 0;

    const input = party === 'alice' ? { a: value } : { b: value };
    const otherParty = party === 'alice' ? 'bob' : 'alice';

    const protocol = await generateProtocol();

    const session = protocol.join(party, input, (to, msg) => {
      assert(to === otherParty, 'Unexpected party');
      socket.send(msg);

      currentBytes += msg.byteLength;

      if (onProgress) {
        onProgress(currentBytes / TOTAL_BYTES);
      }
    });

    this.msgQueue.stream((msg: unknown) => {
      if (!(msg instanceof Uint8Array)) {
        throw new Error('Unexpected message type');
      }

      session.handleMessage(otherParty, msg);

      currentBytes += msg.byteLength;

      if (onProgress) {
        onProgress(currentBytes / TOTAL_BYTES);
      }
    });

    const output = await session.output();

    if (currentBytes !== TOTAL_BYTES) {
      console.error(
        [
          'Bytes sent & received was not equal to TOTAL_BYTES.',
          ' This causes incorrect progress calculations.',
          ` To fix, updated TOTAL_BYTES to ${currentBytes}.`,
        ].join(''),
      );
    }

    if (
      output === null ||
      typeof output !== 'object' ||
      typeof output.main !== 'number'
    ) {
      throw new Error('Unexpected output');
    }

    const result =
      output.main === 0
        ? 'equal'
        : (output.main === 1 && party === 'alice') ||
            (output.main === 2 && party === 'bob')
          ? 'larger'
          : 'smaller';

    return { result, myValue: value };
  }

  /**
   * 发送数字给对方
   */
  sendNumber(value: number): void {
    const { socket } = this;
    assert(socket !== undefined, 'Socket must be set');
    
    const message = JSON.stringify({ type: 'number', value });
    socket.send(new TextEncoder().encode(message));
  }

  /**
   * 等待接收对方的数字
   */
  async receiveNumber(): Promise<number> {
    const value = await this.numberQueue.shift();
    if (typeof value !== 'number') {
      throw new Error('Received invalid number');
    }
    return value;
  }
}
