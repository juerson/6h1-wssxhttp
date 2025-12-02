import { connect } from 'cloudflare:sockets'

class Config {
	static get defaults() {
		return {
			V_UUID4: '8640655f-7920-437a-9b91-2ec452b74b03',
			USER_PROXY: '193.123.90.82:12648', // "host[:port],domain.com,...", 443 port can ignore
			LOG_LEVEL: 'none', // debug, info, error, none
			TIME_ZONE: '8', // timestamp time zone of logs
			BUFFER_SIZE: '64', // Upload/Download buffer size in KiB
			IP_QUERY_PATH: '/ip', // URL path for querying client IP information, empty means disabled
			WS_PATH: '/8640655f/ws', // URL path for ws transport, e.g. '/ws', empty means disabled
			XHTTP_PATH: '/8640655f/xhttp', // URL path for xhttp transport, e.g. '/xhttp', empty means disabled
			XPADDING_RANGE: '100-1000', // Length range of X-Padding response header
			RELAY_SCHEDULER: 'pipe', // yield / pipe
			YIELD_SIZE: '64', // KiB
			YIELD_DELAY: '5', // ms
			PREFERRED_ADDRESS: [
				'r2.dev', 'mqtt.dev', 'cloudflare.dev', 'devprod.cloudflare.dev',
				'preview.devprod.cloudflare.dev', 'radar.cloudflare.com', 'cloudflareclient.com',
				'www.visa.com.sg', 'www.visa.com.hk', 'usa.visa.com'
			]
		}
	}
	constructor(env = {}) {
		Object.assign(this, Config.defaults, env);
		this.#normalizeAll();
	}

	#normalizeAll() {
		// 路径统一化（去除末尾斜杠）
		this.WS_PATH = this.normalizePath(this.WS_PATH);
		this.XHTTP_PATH = this.normalizePath(this.XHTTP_PATH);
		this.IP_QUERY_PATH = this.normalizePath(this.IP_QUERY_PATH);
		// 日志、调度、缓存等数值化
		this.LOG_LEVEL = (this.LOG_LEVEL || 'error').toLowerCase();
		this.RELAY_SCHEDULER = (this.RELAY_SCHEDULER || 'pipe').toLowerCase();
		this.BUFFER_SIZE = (Number(this.BUFFER_SIZE) || 64) * 1024;
		this.YIELD_SIZE = Number(this.YIELD_SIZE) || 64;
		this.YIELD_DELAY = Number(this.YIELD_DELAY) || 5;
		// 预计算的加密/UUID
		this.V_UUID4_BYTES = UuidHelper.parseBytes(this['V_UUID4']);
		this.T_SHA224PWD = Crypto.sha224Hash(this['V_UUID4']);
		// 代理列表（逗号/空格/换行都能分割）
		this.proxyList = Config.parseProxyList(this['USER_PROXY']);
	}

	normalizePath(p) {
		return p?.endsWith('/') ? p.slice(0, -1) : (p ?? '');
	}

	static parseProxyList(str) {
		if (!str) return [];
		return str.split(/[ ,\n\r]+/).filter(Boolean);
	}
}

class Logger {
	static #LOG_LEVELS = { debug: 0, info: 1, error: 2, none: 3 };

	constructor(level = 'info', timeZone = '0') {
		this.id = this.#generateRandomId();
		const offset = Number(timeZone);
		this.timeDriftMs = isNaN(offset) ? 0 : offset * 3_600_000;
		this.levelIdx = Logger.#LOG_LEVELS[(level || 'info').toLowerCase()] ?? Logger.#LOG_LEVELS.info;
	}

	debug(...msg) { if (this.levelIdx <= Logger.#LOG_LEVELS.debug) this.#log('[debug]', ...msg); }
	info(...msg) { if (this.levelIdx <= Logger.#LOG_LEVELS.info) this.#log('[info ]', ...msg); }
	error(...msg) { if (this.levelIdx <= Logger.#LOG_LEVELS.error) this.#log('[error]', ...msg); }

	#generateRandomId() {
		return Math.floor(Math.random() * 90000) + 10000;
	}

	#log(prefix, ...msg) {
		const ts = new Date(Date.now() + this.timeDriftMs).toISOString().slice(0, -1);
		console.log(ts, prefix, `(${this.id})`, ...msg);
	}
}

class Crypto {
	static #K = [
		1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221,
		3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580,
		3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
		2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895,
		666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
		2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
		430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
		1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298
	];
	static #H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	static #encoder = new TextEncoder();

	static sha224Hash(str) {
		if (typeof str !== 'string') throw new TypeError('sha224Hash: input must be a string');
		const rotr = (x, n) => (x >>> n) | (x << (32 - n));
		const msgBytes = Crypto.#encoder.encode(str);
		const bitLength = BigInt(msgBytes.length) * 8n;
		const paddingLen = (56 - (msgBytes.length + 1) % 64 + 64) % 64;
		const totalLen = msgBytes.length + 1 + paddingLen + 8;
		const buffer = new Uint8Array(totalLen);
		buffer.set(msgBytes);
		buffer[msgBytes.length] = 0x80;
		const dataView = new DataView(buffer.buffer);
		dataView.setBigUint64(totalLen - 8, bitLength, false);
		const w = new Uint32Array(64);
		let h = Crypto.#H.slice();
		for (let offset = 0; offset < buffer.length; offset += 64) {
			for (let i = 0; i < 16; i++) {
				w[i] = dataView.getUint32(offset + i * 4, false);
			}
			for (let i = 16; i < 64; i++) {
				const w15 = w[i - 15];
				const w2 = w[i - 2];
				const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
				const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
				w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
			}
			let [a, b, c, d, e, f, g, hh] = h;
			for (let i = 0; i < 64; i++) {
				const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
				const ch = (e & f) ^ (~e & g);
				const temp1 = (hh + S1 + ch + Crypto.#K[i] + w[i]) >>> 0;
				const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
				const maj = (a & b) ^ (a & c) ^ (b & c);
				const temp2 = (S0 + maj) >>> 0;
				hh = g;
				g = f;
				f = e;
				e = (d + temp1) >>> 0;
				d = c;
				c = b;
				b = a;
				a = (temp1 + temp2) >>> 0;
			}
			h[0] = (h[0] + a) >>> 0;
			h[1] = (h[1] + b) >>> 0;
			h[2] = (h[2] + c) >>> 0;
			h[3] = (h[3] + d) >>> 0;
			h[4] = (h[4] + e) >>> 0;
			h[5] = (h[5] + f) >>> 0;
			h[6] = (h[6] + g) >>> 0;
			h[7] = (h[7] + hh) >>> 0;
		}
		return h.slice(0, 7).map(word => word.toString(16).padStart(8, '0')).join('');
	}
}

class UuidHelper {
	static parseBytes(uuid) {
		const cleaned = uuid.replace(/-/g, "")
		if (cleaned.length !== 32) throw new Error('invalid UUID')
		const out = new Uint8Array(16)
		for (let i = 0; i < 16; i++) {
			out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
		}
		return out
	}

	static equals(left, right) {
		if (left.length !== right.length) return false
		for (let i = 0; i < 16; i++) {
			if (left[i] !== right[i]) return false
		}
		return true
	}
}

class PaddingGenerator {
	constructor() {
		this.cache = new Map()
		this.rangeCache = new Map()
	}

	generate(rangeStr) {
		if (!rangeStr || rangeStr === '0' || typeof rangeStr !== 'string') return null

		const { min, max } = this.#parseRange(rangeStr)

		if (!Number.isFinite(min) || min <= 0) return null
		if (!Number.isFinite(max)) return null

		const actualMax = max < min ? min : max
		const len = min === actualMax ? min : Math.floor(Math.random() * (actualMax - min + 1)) + min

		return this.#getZeroPadding(len)
	}

	#parseRange(rangeStr) {
		let range = this.rangeCache.get(rangeStr)
		if (range) return range

		const dashIndex = rangeStr.indexOf('-')
		const min = Number(rangeStr.slice(0, dashIndex === -1 ? rangeStr.length : dashIndex))
		const maxStr = dashIndex === -1 ? null : rangeStr.slice(dashIndex + 1)
		const max = maxStr ? Number(maxStr) : min

		range = { min, max }
		this.rangeCache.set(rangeStr, range)
		return range
	}

	#getZeroPadding(len) {
		let s = this.cache.get(len)
		if (!s) {
			s = '0'.repeat(len)
			this.cache.set(len, s)
		}
		return s
	}
}

class ConnectionManager {
	constructor(logger, proxyList) {
		this.logger = logger
		this.proxyList = proxyList || []
		this.timeout = 5000
	}

	async connect(hostname, port) {
		// Try direct connection
		try {
			this.logger.info(`direct connect [${hostname}]:${port}`)
			return await this.#connectWithTimeout(hostname, port)
		} catch (err) {
			this.logger.debug(`direct connect failed: ${err.message}`)
		}

		// Try proxy connection
		const p = this.#pickRandomProxy()
		if (p) {
			this.logger.info(`proxy [${hostname}]:${port} through [${p.hostname}:${p.port}]`)
			return await this.#connectWithTimeout(p.hostname, p.port)
		}

		throw new Error('all connection attempts failed')
	}

	monitorAbortSignal(signal, remote) {
		if (!signal || !remote) return

		if (signal.aborted) {
			this.#closeRemote(remote)
			return
		}

		signal.addEventListener('abort', () => this.#closeRemote(remote), { once: true })
	}

	#pickRandomProxy() {
		if (!this.proxyList.length) return null;
		const raw = this.proxyList[Math.floor(Math.random() * this.proxyList.length)];
		return this.#splitHostPort(raw);
	}

	#splitHostPort(address) {
		const str = String(address).trim()
		if (str.startsWith('[')) {
			const end = str.indexOf(']')
			if (end !== -1) {
				const host = str.slice(0, end + 1)
				const after = str.slice(end + 1)
				const port = after.startsWith(':') ? Number(after.slice(1)) : 443
				return { hostname: host, port }
			}
		}
		const colonIdx = str.lastIndexOf(':')
		if (colonIdx > -1) {
			const possiblePort = str.slice(colonIdx + 1)
			if (/^\d+$/.test(possiblePort)) {
				const host = str.slice(0, colonIdx)
				const port = Number(possiblePort)
				return { hostname: host, port }
			}
		}
		return { hostname: str, port: 443 }
	}

	async #connectWithTimeout(host, port) {
		return new Promise((resolve, reject) => {
			const conn = connect({ hostname: host, port })
			const timer = setTimeout(() => {
				conn.close?.().catch(() => { })
				reject(new Error('connect timeout'))
			}, this.timeout)

			conn.opened
				.then(() => {
					clearTimeout(timer)
					resolve(conn)
				})
				.catch(err => {
					clearTimeout(timer)
					conn.close?.().catch(() => { })
					reject(err)
				})
		})
	}

	#closeRemote(remote) {
		this.logger.debug("kill remote connection")
		try {
			remote.close()
		} catch (e) {
			this.logger.error(`kill remote error: ${e}`)
		}
	}
}

class StreamManager {
	static #strategyCache = new Map(); // highWaterMark → strategy

	createQueuingStrategy(bufferSize) {
		const highWaterMark = bufferSize > 0 ? bufferSize : 64 * 1024;
		const cached = StreamManager.#strategyCache.get(highWaterMark);
		if (cached) return cached;

		const strategy = {
			highWaterMark,
			size(chunk) {
				return chunk?.byteLength ?? 0;
			},
		};
		StreamManager.#strategyCache.set(highWaterMark, strategy);
		return strategy;
	}

	concatTypedArrays(...arrays) {
		const total = arrays.reduce((sum, a) => sum + (a?.length ?? 0), 0);
		const out = new Uint8Array(total);
		let offset = 0;
		for (const arr of arrays) {
			if (!arr?.length) continue;
			out.set(arr, offset);
			offset += arr.length;
		}
		return out;
	}
}

class WebSocketClient {
	constructor(logger, bufferSize, client, server) {
		this.logger = logger
		this.client = client
		this.server = server
		this.abortCtrl = new AbortController()
		this.signal = this.abortCtrl.signal
		this.isServerOpen = true
		this.reading = true
		this.writing = true

		const streamManager = new StreamManager()
		this.queuingStrategy = streamManager.createQueuingStrategy(bufferSize)
		this.readableController = null

		this.#setupStreams()
	}

	#logError(prefix, err) {
		if (err?.name === 'AbortError') return
		const msg = err instanceof Error ? err.message : String(err)
		this.logger.error(`${prefix} error: ${msg}`)
	}

	#safeAbort(reason) {
		if (this.signal.aborted) return
		try {
			this.abortCtrl.abort(reason)
		} catch (e) {
			this.logger.error('abort failed: ' + (e?.message || e))
		}
	}

	#closeWebSocket(code = 1000, reason = 'Normal Closure') {
		if (!this.isServerOpen) return
		this.isServerOpen = false
		try {
			this.server.close(code, reason)
		} catch (err) {
			this.#logError('close websocket error', err)
		}
	}

	#setDone(type) {
		this[type] = false
		this.logger.debug(`websocket ${type} closed`)
		if (!this.reading && !this.writing) this.#closeWebSocket()
	}

	#handleMessage = (event) => {
		if (!this.reading || !this.readableController) return
		try {
			this.readableController.enqueue(event.data)
		} catch (err) {
			this.#logError('websocket enqueue error', err)
			this.#safeAbort(err)
			this.#setDone('reading')
		}
	}

	#handleError = (event) => {
		if (!this.reading) return
		const msg = event?.error?.message || event?.message || 'Unknown websocket error'
		this.logger.error('websocket error: ' + msg)
		this.readableController?.error?.(event?.error || msg)
		this.#safeAbort(msg)
		this.#setDone('reading')
	}

	#handleClose = (event) => {
		if (!this.isServerOpen && !this.reading) return
		this.isServerOpen = false
		const { code = '', reason = '' } = event || {}
		this.logger.debug(`websocket closed (code=${code}, reason=${reason})`)
		this.readableController?.close?.()
		this.#safeAbort(`WebSocket closed with code ${code} reason: ${reason}`)
		this.#setDone('reading')

		this.server.removeEventListener('message', this.#handleMessage)
		this.server.removeEventListener('error', this.#handleError)
		this.server.removeEventListener('close', this.#handleClose)
	}

	#setupStreams() {
		this.readable = new ReadableStream({
			start: (controller) => {
				this.readableController = controller
				this.server.addEventListener('message', this.#handleMessage)
				this.server.addEventListener('error', this.#handleError)
				this.server.addEventListener('close', this.#handleClose)
			},
			cancel: (reason) => {
				const msg = reason?.message || String(reason || 'Readable cancelled')
				this.logger.debug('websocket reader cancelled: ' + msg)
				this.#safeAbort(msg)
				this.#setDone('reading')
			}
		}, this.queuingStrategy)

		this.writable = new WritableStream({
			write: (chunk) => {
				if (!this.isServerOpen) throw new Error('Cannot send on closed WebSocket')
				try {
					this.server.send(chunk)
				} catch (err) {
					this.#logError('websocket send error', err)
					this.#setDone('writing')
					this.#safeAbort(err)
					throw err
				}
			},
			close: () => this.writing && this.#setDone('writing'),
			abort: (reason) => {
				const msg = reason?.message || String(reason || 'Writable aborted')
				this.#logError('websocket writer aborted', msg)
				this.#setDone('writing')
				this.#safeAbort(msg)
			}
		}, this.queuingStrategy)

		this.resp = new Response(null, { status: 101, webSocket: this.client })
	}

	close(code, reason) {
		this.#closeWebSocket(code, reason)
	}

	readingDone() {
		this.#setDone('reading')
	}
}

class XhttpClient {
	constructor(config, bufferSize, readable) {
		this.config = config
		const streamManager = new StreamManager()
		const paddingGen = new PaddingGenerator()

		const headers = {
			'X-Accel-Buffering': 'no',
			'Cache-Control': 'no-store',
			'Connection': 'Keep-Alive',
			'User-Agent': 'Mozilla/5.0',
			'Content-Type': 'application/grpc'
		}
		const padding = paddingGen.generate(config.XPADDING_RANGE)
		if (padding) headers['X-Padding'] = padding

		const bufferStream = new TransformStream(
			{
				transform(chunk, controller) {
					controller.enqueue(chunk)
				}
			},
			streamManager.createQueuingStrategy(bufferSize)
		)

		this.readable = readable
		this.writable = bufferStream.writable
		this.resp = new Response(bufferStream.readable, { headers })
	}
}

class DataRelay {
	constructor(config, logger, abortSignal) {
		this.config = config
		this.logger = logger
		this.abortSignal = abortSignal
	}

	async relay(client, remote, vls) {
		// 上行（client → remote）
		const up = this.#pump(client, remote, vls.data)
			.catch(err => this.#logError('upload', err))
			.finally(() => client.readingDone && client.readingDone())
		// 下行（remote → client），可能携带 “first response” 包
		const firstResp = (vls.resp && vls.resp.byteLength > 0) ? vls.resp : undefined
		const down = this.#pump(remote, client, firstResp).catch(err => this.#logError('download', err))

		await Promise.allSettled([up, down])
		this.logger.info('connection closed')
	}

	async pipe(src, dst, firstPacket) {
		if (firstPacket && firstPacket.length > 0) {
			const writer = dst.writable.getWriter()
			try {
				await writer.write(firstPacket)
			} finally {
				writer.releaseLock()
			}
		}

		const opt = src.signal ? { signal: src.signal } : undefined
		try {
			await src.readable.pipeTo(dst.writable, opt)
		} catch (e) {
			if (e.name === 'AbortError') dst.writable.close()
			throw e
		}
	}

	async yield(src, dst, firstPacket) {
		const reader = src.readable.getReader()
		const writer = dst.writable.getWriter()

		const p = new Promise((res, rej) => {
			(firstPacket && firstPacket.byteLength ? writer.write(firstPacket) : Promise.resolve())
				.then(() => this.#yieldCopy(res, rej, reader, writer)).catch(rej)
		})

		p.finally(() => {
			reader.releaseLock()
			writer.releaseLock()
		})

		return p
	}

	async #yieldCopy(resolve, reject, reader, writer) {
		const maxChunk = parseInt(this.config.YIELD_SIZE) * 1024
		const delayMs = parseInt(this.config.YIELD_DELAY)
		try {
			let transferred = 0
			while (transferred < maxChunk) {
				if (this.abortSignal?.aborted) throw new DOMException('receive abort signal', 'AbortError')

				const r = await reader.read()
				if (r.value) {
					transferred += r.value.byteLength
					await writer.write(r.value)
				}
				if (r.done) {
					await writer.close()
					resolve()
					return
				}
			}
			await new Promise(res => setTimeout(res, delayMs))
			this.#yieldCopy(resolve, reject, reader, writer)
		} catch (e) {
			reject(e)
		}
	}

	async #pump(src, dst, firstPacket) {
		const method = this.config.RELAY_SCHEDULER === 'yield' ? 'yield' : 'pipe'
		return this[method](src, dst, firstPacket)
	}

	#logError(prefix, err) {
		if (err?.name === 'AbortError') return;
		const msg = err instanceof Error ? err.message : String(err);
		this.logger.error(`${prefix} error: ${msg}`);
	}
}

class ProtocolParser {
	constructor(name) {
		this.name = name
		this.decoder = new TextDecoder()
		this.MAX_HEADER_SIZE = 8 * 1024
		this.streamManager = new StreamManager()
	}

	async readUntil(reader, targetLen, state) {
		if (targetLen > this.MAX_HEADER_SIZE) throw new Error('header too large')

		while (state.bytesRead < targetLen) {
			const { value, done } = await reader.read();
			if (done) throw new Error('not enough data to read');
			const chunk = new Uint8Array(value);
			state.bytesRead += chunk.length;
			if (state.bytesRead > this.MAX_HEADER_SIZE) throw new Error('header too large');
			state.header = this.streamManager.concatTypedArrays(state.header, chunk)
		}
	}

	parseHostname(header, idx, atype) {
		const ATYPE = {
			IPV4: 1,
			DOMAIN_SSELV: 2,
			DOMAIN_NAJORTANDSS: 3,
			IPV6_SSELV: 3,
			IPV6_NAJORTANDSS: 4
		}

		let hostname = ''

		if (atype === ATYPE.IPV4) {
			hostname = header.slice(idx, idx + 4).join('.')
		} else if (atype === ATYPE.DOMAIN_SSELV || atype === ATYPE.DOMAIN_NAJORTANDSS) {
			const len = header[idx]
			hostname = this.decoder.decode(header.slice(idx + 1, idx + 1 + len))
		} else if (atype === ATYPE.IPV6_SSELV || atype === ATYPE.IPV6_NAJORTANDSS) {
			hostname = Array.from({ length: 8 })
				.map((_, i) => {
					const hi = header[idx + i * 2]
					const lo = header[idx + i * 2 + 1]
					return ((hi << 8) | lo).toString(16)
				})
				.join(':')
		}

		return hostname
	}
}

class SselvProtocolParser extends ProtocolParser {
	constructor() {
		super('cfsselv')
	}

	match(buf, config) {
		if (buf.length < 17 || buf[0] !== 0x00) return false

		const uuidBytes = buf.slice(1, 17)
		const payloadLen = buf[17]
		const cmd = buf[1 + 16 + 1 + payloadLen]
		const addrOffset = 1 + 16 + 1 + payloadLen + 1 + 2 + 1
		const atype = buf[addrOffset - 1]

		return UuidHelper.equals(uuidBytes, config.V_UUID4_BYTES) && cmd === 1 && [1, 2, 3].includes(atype)
	}

	async parse(reader, state) {
		await this.readUntil(reader, 1 + 16 + 1, state)
		const h = state.header
		const version = h[0]
		const payloadLen = h[17]
		const addrOffset = 1 + 16 + 1 + payloadLen + 1 + 2 + 1

		await this.readUntil(reader, addrOffset + 1, state)

		const port = (h[addrOffset - 3] << 8) + h[addrOffset - 2]
		const atype = h[addrOffset - 1]

		let headerLen = -1
		if (atype === 1) headerLen = addrOffset + 4
		else if (atype === 3) headerLen = addrOffset + 16
		else if (atype === 2) headerLen = addrOffset + 1 + h[addrOffset]
		else throw new Error('read address type failed')

		await this.readUntil(reader, headerLen, state)

		const hostname = this.parseHostname(state.header, addrOffset, atype)
		const data = state.header.slice(headerLen)
		const resp = new Uint8Array([version, 0])

		return { hostname, port, data, resp }
	}
}

class NajortProtocolParser extends ProtocolParser {
	constructor() {
		super('cfnajort')
	}

	match(buf, config) {
		if (buf.length < 58) return false

		let bufPassword = this.decoder.decode(buf.slice(0, 56))

		return (
			buf[56] === 0x0d &&
			buf[57] === 0x0a &&
			/^[A-Za-z0-9+/=]+$/.test(bufPassword) &&
			bufPassword === config.T_SHA224PWD &&
			buf[58] === 1 &&
			[1, 3, 4].includes(buf[59])
		)
	}

	async parse(reader, state) {
		const PASS_LEN = 56
		await this.readUntil(reader, PASS_LEN + 2, state)
		const h = state.header
		const SOCKS5_BASE = PASS_LEN + 2

		await this.readUntil(reader, SOCKS5_BASE + 2, state)
		const atype = h[SOCKS5_BASE + 1]

		let addressLen = 0
		let extra = 0

		if (atype === 1) addressLen = 4
		else if (atype === 4) addressLen = 16
		else if (atype === 3) {
			await this.readUntil(reader, SOCKS5_BASE + 2 + 1, state)
			extra = 1
			addressLen = h[SOCKS5_BASE + 2]
		} else throw new Error(`invalid address type: ${atype}`)

		const headerLen = SOCKS5_BASE + 2 + extra + addressLen + 4
		await this.readUntil(reader, headerLen, state)

		const addrStart = SOCKS5_BASE + 2 + extra
		const hostname = this.parseHostname(h, addrStart - 1, atype)
		const portIdx = addrStart + addressLen
		const port = (h[portIdx] << 8) + h[portIdx + 1]
		const data = h.slice(headerLen)

		return { hostname, port, data, resp: null }
	}
}

class SkcoswodahsProtocolParser extends ProtocolParser {
	constructor() {
		super('cfskcoswodahs')
	}

	match(buf, config) {
		if (buf.length < 3) return false  // 至少要有 atype + port

		const atype = buf[0]
		if (![1, 3, 4].includes(atype)) return false

		// 域名至少得有长度字节
		if (atype === 3 && buf.length < 2) return false

		return true
	}

	async parse(reader, state) {
		await this.readUntil(reader, 1, state)
		const h = state.header
		const atype = h[0]

		let addressLen = 0
		let extra = 0
		if (atype === 1) {
			addressLen = 4
			await this.readUntil(reader, 1 + 4 + 2, state)  // atype + ipv4 + port
		} else if (atype === 4) {
			addressLen = 16
			await this.readUntil(reader, 1 + 16 + 2, state)
		} else if (atype === 3) {
			await this.readUntil(reader, 2, state)
			const len = state.header[1]
			extra = 1
			addressLen = len
			await this.readUntil(reader, 2 + len + 2, state) // atype + len + hostname + port
		} else {
			throw new Error(`invalid address type: ${atype}`)
		}

		const header = state.header
		const addrStart = 1 + extra
		const portIdx = addrStart + addressLen
		const port = (header[portIdx] << 8) | header[portIdx + 1]

		let hostname = ""
		if (atype === 1) { // IPv4
			hostname = [...header.slice(addrStart, addrStart + 4)].join(".")
		} else if (atype === 4) { // IPv6
			const parts = []
			for (let i = 0; i < 16; i += 2) {
				parts.push(((header[addrStart + i] << 8) | header[addrStart + i + 1]).toString(16))
			}
			hostname = parts.join(":")
		} else if (atype === 3) {
			hostname = this.decoder.decode(header.slice(addrStart, addrStart + addressLen))
		}

		const data = header.slice(portIdx + 2)

		return { hostname, port, data, resp: null }
	}
}

class ProtocolRegistry {
	constructor() {
		this.protocols = [new SselvProtocolParser(), new NajortProtocolParser(), new SkcoswodahsProtocolParser()]
	}

	async parseHeader(config, client) {
		const reader = client.readable.getReader()
		const state = { bytesRead: 0, header: new Uint8Array() }

		try {
			// 读取初始字节用于协议识别
			const parser = new ProtocolParser('temp')
			await parser.readUntil(reader, 64, state)
			const buf = state.header

			// 遍历协议表找到匹配的协议
			for (const proto of this.protocols) {
				let matched = false
				try {
					matched = proto.match(buf, config)
				} catch (e) {
					continue
				}
				// 找到匹配的协议后交给它继续读取剩余内容
				if (matched) {
					try {
						const result = await proto.parse(reader, state)
						return result
					} catch (e) {
						throw new Error(`Failed to parse ${proto.name}: ${e.message}`)
					}
				}
			}

			throw new Error('Unrecognized protocol: not in [sselV, najorT, skcoswodahS]')
		} catch (err) {
			throw new Error(`Parse client header failed: ${err.message}`)
		} finally {
			reader.releaseLock()
		}
	}
}

class LinkGenerator {
	static PARAMS = {
		SSELV_WS: atob('ZW5jcnlwdGlvbj1ub25lJnNlY3VyaXR5PXRscyZhbGxvd0luc2VjdXJlPTEmdHlwZT13cw=='),
		NAJORT_WS: atob('c2VjdXJpdHk9dGxzJmFsbG93SW5zZWN1cmU9MSZ0eXBlPXdz'),
		SKCOSWODAHS_WS: atob('cGx1Z2luPXYycmF5LXBsdWdpbjt0bHM7bXV4JTNEMDttb2RlJTNEd2Vic29ja2V0Ow=='),
		SSELV_XHTTP: atob('ZW5jcnlwdGlvbj1ub25lJnNlY3VyaXR5PXRscyZhbGxvd0luc2VjdXJlPTEmdHlwZT14aHR0cA=='),
		NAJORT_XHTTP: atob('c2VjdXJpdHk9dGxzJmFsbG93SW5zZWN1cmU9MSZ0eXBlPXhodHRw'),
	}
	#httpsPorts = [443, 2053, 2083, 2087, 2096, 8443]

	constructor(config) {
		this.config = config
	}

	generate(urlObj, path) {
		if (urlObj.searchParams.get('uuid') !== this.config.V_UUID4) return null
		const { hostname: host, pathname } = urlObj

		if (path.endsWith(this.config.WS_PATH)) return this.#generateLinks(host, pathname, 'ws')
		if (path.endsWith(this.config.XHTTP_PATH)) return this.#generateLinks(host, pathname, 'xhttp')
		return null
	}

	#generateLinks(host, pathname, type) {
		const isWs = type === 'ws'
		const sselvParams = isWs ? LinkGenerator.PARAMS.SSELV_WS : LinkGenerator.PARAMS.SSELV_XHTTP
		const najortParams = isWs ? LinkGenerator.PARAMS.NAJORT_WS : LinkGenerator.PARAMS.NAJORT_XHTTP
		const mode = isWs ? '' : '&mode=stream-one'

		const links = this.config.PREFERRED_ADDRESS.flatMap(addr => {
			const [first, second, third] = this.#randomPorts(this.#httpsPorts, 3, 443)
			const sselv = `${atob('dmxlc3M6Ly8=')}${this.config.V_UUID4}@${addr}:${first}?${sselvParams}&host=${host}&path=${encodeURIComponent(pathname)}${mode}#${atob('dmxlc3Mt')}${type}-tls`
			const najort = `${atob('dHJvamFuOi8v')}${this.config.V_UUID4}@${addr}:${second}?${najortParams}&host=${host}&path=${encodeURIComponent(pathname)}${mode}#${atob('dHJvamFuLQ==')}${type}-tls`
			let output = [sselv, najort]
			if (isWs) output.push(`${atob('c3M6Ly8=')}${btoa(`none:${this.config.V_UUID4}`)}@${addr}:${third}?${LinkGenerator.PARAMS.SKCOSWODAHS_WS}${encodeURIComponent(`host=${host};path=${pathname}`)}#${atob('c2hhZG93c29ja3Mt')}${type}-tls`)
			return output
		})

		return links.join('\n')
	}

	#randomPorts(arr, count = 3, def = 443) {
		if (!Array.isArray(arr)) throw new TypeError('Expected an array');
		const picked = [...arr].sort(() => Math.random() - 0.5).slice(0, count);
		return [...picked, ...Array(count - picked.length).fill(def)];
	}
}

class IPInfoProvider {
	getInfo(request) {
		const cf = request.cf || {}

		return {
			ip: request.headers.get('cf-connecting-ip') ?? '',
			userAgent: request.headers.get('user-agent') ?? '',
			organization: cf.asOrganization ?? '',
			city: cf.city ?? '',
			continent: cf.continent ?? '',
			country: cf.country ?? '',
			latitude: cf.latitude ?? '',
			longitude: cf.longitude ?? '',
			region: cf.region ?? '',
			regionCode: cf.regionCode ?? '',
			timezone: cf.timezone ?? ''
		}
	}
}

class ClientProcessor {
	constructor(config, logger) {
		this.config = config
		this.logger = logger
		this.connectionManager = new ConnectionManager(logger, config.proxyList)
		this.protocolRegistry = new ProtocolRegistry()
	}

	async process(client, ctx) {
		try {
			// 解析协议头部
			const vls = await this.protocolRegistry.parseHeader(this.config, client)
			// 建立远端 TCP 连接
			const remote = await this.connectionManager.connect(vls.hostname, vls.port)
			// 数据转发（pipe / yield）
			const relay = new DataRelay(this.config, this.logger, client.signal)
			if (ctx && typeof ctx.waitUntil === 'function') {
				ctx.waitUntil(relay.relay(client, remote, vls))
			} else {
				await relay.relay(client, remote, vls)
			}
			// 监控 AbortSignal（如果客户端关闭则销毁远端）
			this.connectionManager.monitorAbortSignal(client.signal, remote)
			return true
		} catch (e) {
			this.logger.error(`handle client error: ${e.message}`)
			if (client && typeof client.close === 'function') {
				try { client.close() } catch { }
			}
			return false
		}
	}
}

class AppWorker {
	constructor(env) {
		this.config = new Config(env)
		this.logger = new Logger(this.config.LOG_LEVEL, this.config['TIME_ZONE'])
		this.clientProcessor = new ClientProcessor(this.config, this.logger)
		this.linkGenerator = new LinkGenerator(this.config)
		this.ipInfoProvider = new IPInfoProvider()
		this.BAD_REQUEST = new Response(null, { status: 400, statusText: 'BAD_REQUEST' })
	}

	async handleWs(request) {
		this.logger.debug('accept ws client')
		let [client, server] = Object.values(new WebSocketPair())
		server.accept()
		const wsClient = new WebSocketClient(this.logger, this.config.BUFFER_SIZE, client, server)
		try {
			this.clientProcessor.process(wsClient)
			return wsClient.resp
		} catch (err) {
			this.logger.error(`accept ws client error: ${err.message}`)
			wsClient.close && wsClient.close()
			return this.BAD_REQUEST
		}
	}

	async handleXhttp(request, ctx) {
		this.logger.debug('accept xhttp client')
		const body = request.body
		if (!body) {
			this.logger.error('xhttp request has no body')
			return this.BAD_REQUEST
		}
		const client = new XhttpClient(this.config, this.config.BUFFER_SIZE, body)
		const ok = await this.clientProcessor.process(client, ctx)
		return ok ? client.resp : this.BAD_REQUEST
	}

	async handleGet(request, url, pathname) {
		if (this.config.IP_QUERY_PATH && url.pathname.endsWith(this.config.IP_QUERY_PATH)) {
			const info = this.ipInfoProvider.getInfo(request);
			return new Response(JSON.stringify(info), {
				headers: { 'content-type': 'application/json;charset=UTF-8' },
			});
		}
		const links = this.linkGenerator.generate(url, pathname);
		if (links) {
			return new Response(links, {
				headers: { 'content-type': 'text/plain;charset=UTF-8' },
			});
		}
		return new Response('Hello World!');
	}

	async fetch(request, ctx) {
		const url = new URL(request.url);
		const p = this.config.normalizePath(url.pathname);
		const upgrade = request.headers.get('Upgrade');
		if (upgrade === 'websocket' && p === this.config.WS_PATH) {
			return await this.handleWs(request);
		}
		if (request.method === 'POST' && p === this.config.XHTTP_PATH) {
			return await this.handleXhttp(request, ctx);
		}
		if (request.method === 'GET' && !upgrade) {
			return this.handleGet(request, url, p);
		}
		return this.BAD_REQUEST;
	}
}

export default {
	async fetch(request, env, ctx) {
		const worker = new AppWorker(env)
		return await worker.fetch(request, ctx)
	}
}
