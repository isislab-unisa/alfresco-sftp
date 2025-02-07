
const path = require('path');
const express = require('express');
const expressWs = require('express-ws');
const asyncHandler = require('express-async-handler');
const logger = require('cyber-express-logger');
const sftp = require('ssh2-sftp-client');
const crypto = require('crypto');
const mime = require('mime');
const bodyParser = require('body-parser');
const archiver = require('archiver');
const rawBodyParser = bodyParser.raw({
	limit: '16mb',
	type: '*/*'
});
const dayjs = require('dayjs');
const dayjsAdvancedFormat = require('dayjs/plugin/advancedFormat');
dayjs.extend(dayjsAdvancedFormat);
const utils = require('web-resources');
const Electron = require('electron');
const config = require('./config.json');

/** Generates a SHA-256 hash for a given object. */
const getObjectHash = (obj) => {
	const hash = crypto.createHash('sha256');
	hash.update(JSON.stringify(obj));
	return hash.digest('hex');
}

/**
 * Class that represents credentials for a connection.
 */
class Credentials {
	/**
	 * @param {string} name - The name of the connection (used for display)
	 * @param {string} host - The hostname of the SFTP server
	 * @param {number} port - The port number of the SFTP server
	 * @param {string} username - The username for the SFTP server
	 * @param {string} path - The path to the directory on the SFTP server
	 * @param {string} password - The password for the SFTP server (can be empty if using a key)
	 * @param {string} privateKey - The private key for the SFTP server (can be empty if using a password)
	 */
	constructor(name, host, port, username, path, password, privateKey) {
		if (!password && !privateKey) {
			throw new Error("Authentication method not provided. Specify 'password' or 'privateKey'.");
		}

		if (password && privateKey) {
			throw new Error("Both 'password' and 'privateKey' provided. Specify only one authentication method.");
		}

		/**
		 * The name of the connection (used for display)
		 * @type {string}
		 */
		this.name = name;
		/**
		 * The hostname of the SFTP server
		 * @type {string}
		 */
		this.host = host;
		/**
		 * The port number of the SFTP server
		 * @type {number}
		 * @default 22
		 */
		this.port = port || 22;
		/**
		 * The username for the SFTP server
		 * @type {string}
		 */
		this.username = username;
		/**
		 * The path to the directory on the SFTP server
		 * @type {string}
		 * @default "/"
		 */
		this.path = path || '/';
		/**
		 * The password for the SFTP server (can be empty if using a key)
		 * @type {string | undefined}
		 * @default undefined
		 */
		this.password = password || undefined;
		/**
		 * The private key for the SFTP server (can be empty if using a password)
		 * @type {string | undefined}
		 * @default undefined
		 */
		this.privateKey = privateKey || undefined;
	}

	/**
	 * Generates a hash for the connection options using the **host, port, username, password, sshKey**.
	 * @returns {string} The hash of the connection options
	 */
	getHash() {
		return getObjectHash({
			host: this.host,
			port: this.port,
			username: this.username,
			password: this.password,
			privateKey: this.privateKey
		});
	}
}

/**
 * Class that represents a single SFTP connection.
 */
class SftpConnection {
	/**
	 * @param {string} key - Can be an UUID or the hash of the connection options
	 */
	constructor(key) {
		/** 
		 * The key of the connection. 
		 * @type {string}
		 */
		this.key = key;
		/** 
		 * The credentials for the SFTP connection. 
		 * @type {Credentials}
		 */
		this.credentials = null;
		/** 
		 * The hash of the credentials. 
		 * Composed of the **host, port, username, password, key**. 
		 * @type {string}
		 */
		this.credentialsHash = null;
		/**
		 * The timestamp of the credentials creation.
		 * @type {number}
		 */
		this.credentialsCreationTime = null;
		/** 
		 * The SFTP session object. 
		 * @type {sftp}
		 */
		this.session = null;
		/** 
		 * The timestamp of the last activity. 
		 * @type {number}
		 */
		this.lastSessionActivity = null;
	}

	/**
	 * Adds the credentials for the SFTP connection.
	 * @param {Credentials} credentials - The credentials for the SFTP connection
	 */
	setCredentials(credentials) {
		this.credentials = credentials;
		this.credentialsHash = credentials.getHash();
		this.credentialsCreationTime = Date.now();
	}

	/**
	 * Sets the SFTP session object for the connection and updates the timestamp of the last activity.
	 * @param {sftp} session - The SFTP session object
	 */
	setSession(session) {
		this.session = session;
		this.lastSessionActivity = Date.now();
	}

	/**
	 * Updates the timestamp of the last activity.
	 */
	updateLastSessionActivity() {
		this.lastSessionActivity = Date.now();
	}	

	/**
	 * Closes the SFTP session and sets it to null.
	 */
	closeSession() {
		if (this.session && typeof this.session.close === 'function') {
			this.session.close();
		}
		this.session = null;
		this.lastSessionActivity = null;
	}
}

/**
 * Class that manages multiple SFTP connections.
 */
class SftpConnectionManager {
	/**
	 * **key**: hash or UUID
	 * 
	 * **value**: instance of SftpConnection
	 */
	constructor() {
		/**
		 * The map of SFTP connections.
		 * 
		 * @type {Map<string, SftpConnection>}
		 */
		this.connections = new Map(); 
	}

	/**
	 * Adds a new SFTP connection.
	 * 
	 * If you need to add an existing connection, use `connections.set(key, connection)`.
	 * @param {string} key - The UUID to identify the connection
	 * @param {Credentials} credentials - The credentials for the SFTP connection
	 * @returns {SftpConnection} The new connection object
	 */
	addNewConnection(key, credentials) {
		if (this.connections.has(key)) {
			throw new Error(`Connection with key '${key}' already exists.`);
		}

		const connection = new SftpConnection(key);
		connection.setCredentials(credentials);
		
		this.connections.set(key, connection);

		return connection;
	}

	/**
	 * Sets the SFTP session object for an existing connection.
	 * @param {string} key - The key of the connection
	 * @param {sftp} session - The SFTP session object
	 */
	setConnectionSession(key, session) {
		const connection = this.connections.get(key);

		if (!connection) {
			throw new Error(`Connection with key '${key}' does not exist.`);
		}
		
		connection.setSession(session);
	}

	/**
	 * Gets an existing connection by key.
	 * @param {string} key - The key of the connection
	 * @returns {SftpConnection | undefined} The connection object or `undefined` if it does not exist
	 */
	getConnection(key) {
		return this.connections.get(key);
	}

	/**
	 * Gets a list of connections by credentials.
	 * @param {string} host - The hostname of the SFTP server
	 * @param {number} port - The port number of the SFTP server
	 * @param {string} username - The username for the SFTP server
	 * @param {string} password - The password for the SFTP server
	 * @param {string} privateKey - The private key for the SFTP server
	 * @returns {SftpConnection[]} An array of connections with the same credentials
	 */
	getConnectionByCredentials(host, port, username, password, privateKey) {
		const result = [];
		for (const connection of this.connections.values()) {
			if (connection.credentials.host === host && 
				connection.credentials.port == port && 
				connection.credentials.username === username &&
				(connection.credentials.password === password || connection.credentials.privateKey === privateKey)) {
					result.push(connection);
			}
		}
		
		return result;
	}

	/**
	 * Removes an existing connection by key.
	 * @param {string} key - The key of the connection
	 * @returns {boolean} True if the connection was removed, false otherwise
	 */
	removeConnection(key) {
		const connection = this.connections.get(key);
		
		if (connection) {
			connection.closeSession();
			this.connections.delete(key);
			return true;
		}
		return false;
	}

	/**
	 * Gets all the connections.
	 * @returns {SftpConnection[]} An array of all the connections
	 */
	getAllConnections() {
		return Array.from(this.connections.values());
	}


	/**
	 * Gets all the credentials.
	 * @returns {Object} An object with the credentials of all the connections
	 */
	getAllCredentials() {
		let credentials = {};

		for (const connection of this.getAllConnections()) {
			credentials[connection.key] = connection.credentials;
		}
		
		return credentials;
	}

	/**
	 * Gets all the sessions.
	 * @returns {Object} An object with the sessions of all the connections
	 */
	getAllSessions() {
		let sessions = {};

		for (const connection of this.getAllConnections()) {
			sessions[connection.key] = connection.session;
		}

		return sessions;
	}
}

//============================//
//        GENERAL API         //
//============================//


/**
 * Normalizes a given file path to ensure it uses forward slashes
 * and removes any redundant slashes. 
 */
const normalizeRemotePath = (remotePath) => {
	remotePath = path.normalize(remotePath).replace(/\\/g, '/');
	const split = remotePath.split('/').filter(String);
	const joined = `/${split.join('/')}`;
	return joined;
};

/**
 * Container for all active connections and credentials.
 */
const sftpConnections = new SftpConnectionManager();

/**
 * Manages SFTP sessions, either reusing existing ones or creating new ones.
 * @param {Response} res The response to send to the request if there is an error.
 * @param {sftp.ConnectOptions} sftpConnectionOptions The SFTP connection parameters.
 * @param {string} connectionKey The key of the connection.
 * @param {boolean} [forceCreation=false] Whether to force the creation of a new session.
 * @returns {Promise<sftp>|null} The SFTP session object, or an error if the connection failed.
 */
const getSession = async (res, sftpConnectionOptions, connectionKey, forceCreation = false) => {
	const username = sftpConnectionOptions.username;
	const host = sftpConnectionOptions.host;
	const port = sftpConnectionOptions.port;
	const address = `${username}@${host}:${port}`;
	
	const connection = sftpConnections.getConnection(connectionKey);

	if (!connection) {
		return res ? res.sendError(`Connection not found with key '${connectionKey}' while connecting to ${address}`) : null;
	}

	if (!forceCreation && connection.session) {
		// There is already an active session for the connection
		console.log(`Using existing connection to ${address}`);
		connection.updateLastSessionActivity();
		return connection.session;
	}

	// Create a new session
	// There should be already a connection with the same credentials,
	// created with a previous request to `/api/sftp/credentials/create`
	console.log(`Creating new session to ${address}`);
	const session = new sftp();
	connection.setSession(session);

	const deleteThisConnection = () => {
		const key = connection.key;
		sftpConnections.removeConnection(key);
		console.log(`Session to ${address} closed`);
	}

	// Handle session events
	session.on('end', () => {
		deleteThisConnection();
	});
	session.on('close', () => {
		deleteThisConnection();
	});

	try {
		// Connect to the SFTP server
		await session.connect(sftpConnectionOptions);
		connection.updateLastSessionActivity();
		console.log(`Connected to ${address}`);
	} catch (error) {
		deleteThisConnection();
		console.log(`Connection to ${address} failed`);
		return res ? res.sendError(error) : null;
	}

	return session;
};

/** Express server */
const srv = express();

// Express WebSocket middleware
expressWs(srv, undefined, {
	wsOptions: {
		maxPayload: 1024 * 1024 * 4
	}
});

srv.use(logger());

/** The directory of the `web` folder containing the static files */
const staticDir = path.join(__dirname, 'web');
srv.use(express.static(staticDir));

console.log(`Serving static files from ${staticDir}`);

/**
 * Initializes the API by: 
 * - setting up in the response object some custom methods to send data and errors
 * - validating request headers
 * - establishing an SFTP session
 */
const initApi = asyncHandler(async (req, res, next) => {
	// Custom method to send a JSON response with a specified status code
	res.sendData = (status = 200) => res.status(status).json(res.data);

	// Custom method to send an error JSON response
	res.sendError = (error, status = 400) => {
		res.data.success = false;
		res.data.error = `${error}`.replace('Error: ', '');
		res.sendData(status);
	}

	// Set the success flag to true by default
	res.data = {
		success: true
	};

	// Get the connection options from the request headers
	// These are set in main.js in getHeaders()
	req.connectionOpts = {
		host: req.headers['sftp-host'],
		port: req.headers['sftp-port'] || 22,
		username: req.headers['sftp-username'],

		// Decode the password and private key from URI encoding
		password: decodeURIComponent(req.headers['sftp-password'] || '') || undefined,
		privateKey: decodeURIComponent(req.headers['sftp-private-key'] || '') || undefined,
	};

	req.connectionKey = req.headers['sftp-connection-key'];

	// Validate the connection options
	if (!req.connectionKey) {
		return res.sendError('Missing connection key');
	}
	if (!req.connectionOpts.host) {
		return res.sendError('Missing host header');
	}
	if (!req.connectionOpts.username) {
		return res.sendError('Missing username header');
	}
	if (!req.connectionOpts.password && !req.connectionOpts.privateKey) {
		return res.sendError('Missing password or key header');
	}

	// Get the SFTP session
	req.session = await getSession(res, req.connectionOpts, req.connectionKey);

	if (!req.session) {
		// If the session could not be created, 
		// the error has already been sent
		return;
	}

	next();
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//~~~~~~~~~~~MY API~~~~~~~~~~~//
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

// Get the number of credentials present in the server
srv.get('/api/sftp/credentials', async (req, res) => {
	const length = Object.keys(sftpConnections.getAllCredentials()).length;
	res.json({ success: true, numOfCredentials: length });
});

// Get the number of sessions present in the server
srv.get('/api/sftp/sessions', async (req, res) => {
	const length = Object.keys(sftpConnections.getAllSessions()).length;
	res.json({ success: true, numOfSessions: length });
});

// Get the credentials of a specific connection
srv.get('/api/sftp/credentials/:key', async (req, res) => {
	const key = req.params.key;
	const connection = sftpConnections.getConnection(key);

	if (connection) {
		res.json({ success: true, key: connection.key, credentials: connection.credentials });
	} else {
		res.status(404).json("Not found");
	}
});

srv.post('/api/sftp/credentials/create', rawBodyParser, async (req, res) => {
	let data;

	try {
		data = JSON.parse(req.body);
	} catch (error) {
		console.log(error);
		res.status(500).json({ success: false, error: "Server JSON parse error" });
	}

	try {
		const credentials = new Credentials(
			data.name,
			data.host,
			data.port,
			data.username,
			data.path,
			data.password,
			data.privateKey
		);

		const key = crypto.randomUUID();
		const connection = sftpConnections.addNewConnection(key, credentials);
		res.json({ success: true, connection_uuid: connection.key });
	} catch (error) {
		res.status(400).json({ success: false, error: error.message });
	}
})

srv.get('/api/sftp/credentials/delete/:key', async (req, res) => {
	const key = req.params.key;

	if (sftpConnections.removeConnection(key)) {
		res.json({ success: true, deleted: key });
	} else {
		res.status(404).json({ success: false, error: `Object '${key}' not found` });
	}
});


/** Stores the association between the generated keys and the corresponding requests */
const keyedRequests = {};

// Generates a random key and associates it with the incoming request
srv.get('/api/sftp/key', initApi, async (req, res) => {
	res.data.key = utils.randomHex(32);
	keyedRequests[res.data.key] = req;
	res.sendData();
});

//============================//
//      DIRECTORIES API       //
//============================//

// Get the list of files and directories in a given path on the SFTP server
srv.get('/api/sftp/directories/list', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	// Whether to include files in the list or just directories
	res.data.includesFiles = req.query.dirsOnly === 'true' ? false : true;

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Get the list of files and directories
		res.data.list = await session.list(res.data.path);

		if (res.data.list && !res.data.includesFiles) {
			// Filter out files if only directories are requested
			res.data.list = res.data.list.filter(item => item.type === 'd');
		}

		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// WebSocket endpoint to search for files and directories in a given path on the SFTP server
srv.ws('/api/sftp/directories/search', async (ws, wsReq) => {
	if (!wsReq.query.key) {
		return ws.close();
	}

	// Get the request associated with the key
	const req = keyedRequests[wsReq.query.key];

	if (!req) {
		return ws.close();
	}

	// Create the session and throw an error if it fails
	const session = await getSession(null, req.connectionOpts, req.connectionKey, true);

	if (!session) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Failed to create session!'
		}));
		return ws.close();
	}

	// Normalize the file path or throw an error if it's missing
	const filePath = normalizeRemotePath(wsReq.query.path);
	if (!filePath) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Missing path'
		}));
		return ws.close();
	}

	// Get the query
	const query = wsReq.query.query;
	if (!query) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Missing query'
		}));
		return ws.close();
	}

	const host = req.connectionOpts.host;
	const port = req.connectionOpts.port;
	const username = req.connectionOpts.username;
	
	const address = `${username}@${host}:${port}`;

	const connection = sftpConnections.getConnection(req.connectionKey);

	if (!connection) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Connection not found'
		}));
		return ws.close();
	}

	// Update the session activity periodically to keep the session active
	const updateActivity = () => {
		connection.updateLastSessionActivity();
	};

	let interval;
	interval = setInterval(updateActivity, 1000 * 1);

	// Handle websocket closure
	let isClosed = false;
	ws.on('close', () => {
		console.log(`Directory search websocket closed`);
		connection.closeSession();
		clearInterval(interval);
		isClosed = true;
	});

	// Listen for messages
	console.log(`Websocket opened to search directory ${address}$${filePath}`);

	/** Function to get a directory listing */
	const scanDir = async (dirPath) => {
		try {
			const list = await session.list(dirPath);
			return [...list].sort((a, b) => {
				// Sort by name
				if (a.name < b.name) return -1;
				if (a.name > b.name) return 1;
				return 0;
			});
		} catch (error) {
			return null;
		}
	};

	let matchedFiles = [];
	let lastSend = 0;
	/** Function to send a list when there are enough files */
	const sendList = () => {
		if (matchedFiles.length > 0) {
			ws.send(JSON.stringify({
				success: true,
				status: 'list',
				list: matchedFiles
			}));
			matchedFiles = [];
			lastSend = Date.now();
		}
	};

	/** Function to recursively search a directory */
	const recurse = async dirPath => {
		if (isClosed) return;
		ws.send(JSON.stringify({
			success: true,
			status: 'scanning',
			path: dirPath
		}));
		const list = await scanDir(dirPath);
		if (!list) {
			ws.send(JSON.stringify({
				success: false,
				error: `Failed to scan directory ${dirPath}`
			}));
			return;
		}
		for (const file of list) {
			if (isClosed) return;
			file.path = `${dirPath}/${file.name}`;
			if (file.name.toLowerCase().includes(query.toLowerCase())) {
				matchedFiles.push(file);
			}
			if ((Date.now() - lastSend) > 1000) sendList();
			if (file.type == 'd') {
				await recurse(file.path);
			}
		}
	};

	// Start the search
	await recurse(filePath);

	if (isClosed) {
		return;
	}

	sendList();

	// Send a complete message
	ws.send(JSON.stringify({ success: true, status: 'complete' }));

	// Close the websocket
	ws.close();
});

// Create a directory on the SFTP server
srv.post('/api/sftp/directories/create', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Create the directory
		await session.mkdir(res.data.path);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Delete a directory on the SFTP server
srv.delete('/api/sftp/directories/delete', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Delete the directory
		await session.rmdir(res.data.path, true);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

//============================//
//         FILES API          //
//============================//

// Check if a file or directory exists on the SFTP server and store it's type
srv.get('/api/sftp/files/exists', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		const type = await session.exists(res.data.path);
		res.data.exists = type !== false;
		res.data.type = type;
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Create a file on the SFTP server
srv.post('/api/sftp/files/create', initApi, rawBodyParser, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Upload the file to the specified path on the SFTP server
		await session.put(req.body, res.data.path);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Append data to a file on the SFTP server
srv.put('/api/sftp/files/append', initApi, rawBodyParser, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Append the data to the file
		await session.append(req.body, res.data.path);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// WebSocket endpoint to append data to a file on the SFTP server
srv.ws('/api/sftp/files/append', async (ws, wsReq) => {
	if (!wsReq.query.key)
		return ws.close();

	// Get the request associated with the key
	const req = keyedRequests[wsReq.query.key];

	if (!req) {
		return ws.close();
	}

	// Create the session and throw an error if it fails
	const session = await getSession(null, req.connectionOpts, req.connectionKey, true);

	if (!session) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Failed to create session!'
		}));
		return ws.close();
	}

	// Normalize the file path or throw an error if it's missing
	const filePath = normalizeRemotePath(wsReq.query.path);
	if (!filePath) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Missing path'
		}));
		return ws.close();
	}

	const host = req.connectionOpts.host;
	const port = req.connectionOpts.port;
	const username = req.connectionOpts.username;
	
	const address = `${username}@${host}:${port}`;

	const connection = sftpConnections.getConnection(req.connectionKey);

	if (!connection) {
		ws.send(JSON.stringify({
			success: false,
			error: 'Connection not found'
		}));
		return ws.close();
	}

	// Handle websocket closure
	ws.on('close', () => {
		connection.closeSession();
		console.log(`File append websocket closed`);
	});

	// Listen for messages
	console.log(`Websocket opened to append to ${address}$${filePath}`);

	let isWriting = false;
	ws.on('message', async (data) => {
		// If we're already writing, send an error
		if (isWriting) {
			return ws.send(JSON.stringify({
				success: false,
				error: 'Writing in progress'
			}));
		}
		try {
			// Append the data to the file
			isWriting = true;
			await session.append(data, filePath);
			ws.send(JSON.stringify({ success: true }));
		} catch (error) {
			ws.send(JSON.stringify({
				success: false,
				error: error.toString()
			}));
			return ws.close();
		}
		isWriting = false;
		// Update the session activity
		connection.updateLastSessionActivity();
	});

	// Send a ready message
	ws.send(JSON.stringify({ success: true, status: 'ready' }));
});

// Delete a file on the SFTP server
srv.delete('/api/sftp/files/delete', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Delete the file
		await session.delete(res.data.path);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Move a file on the SFTP server
srv.put('/api/sftp/files/move', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.pathOld = normalizeRemotePath(req.query.pathOld);
	res.data.pathNew = normalizeRemotePath(req.query.pathNew);

	if (!res.data.pathOld) {
		return res.sendError('Missing source path', 400);
	}
	if (!res.data.pathNew) {
		return res.sendError('Missing destination path', 400);
	}

	try {
		// Move (or rename) the file
		await session.rename(res.data.pathOld, res.data.pathNew);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Copy a file to a directory on the SFTP server
srv.put('/api/sftp/files/copy', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.pathSrc = normalizeRemotePath(req.query.pathSrc);
	res.data.pathDest = normalizeRemotePath(req.query.pathDest);

	if (!res.data.pathSrc) {
		return res.sendError('Missing source path', 400);
	}
	if (!res.data.pathDest) {
		return res.sendError('Missing destination path', 400);
	}

	try {
		// Copy the file (or even a directory?)
		await session.rcopy(res.data.pathSrc, res.data.pathDest);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Change the permissions of a file on the SFTP server
srv.put('/api/sftp/files/chmod', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	res.data.mode = req.query.mode;

	try {
		// Change the permissions of the file
		await session.chmod(res.data.path, res.data.mode);
		res.sendData();
	} catch (error) {
		res.sendError(error);
	}
});

// Get the metadata of a file on the SFTP server
srv.get('/api/sftp/files/stat', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;
	res.data.path = normalizeRemotePath(req.query.path);

	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	let stats = null;
	try {
		// Get the metadata of the file
		stats = await session.stat(res.data.path);
	} catch (error) {
		return res.sendError(error, 404);
	}

	res.data.stats = stats;
	res.sendData();
});

//============================//
//     DOWNLOAD HANDLERS      //
//============================//

/**
 * Handles the download of a single file from a remote SFTP server.
 *
 * @param {Object} connectionOpts - The connection options for the SFTP server.
 * @param {string} connectionKey - The key of the connection.
 * @param {Object} res - The HTTP response object.
 * @param {string} remotePath - The remote file path on the SFTP server.
 * @param {Object} stats - The file statistics object.
 * 
 * @throws {Error} If the remote path is not a file.
 * @throws {Error} If the session creation fails.
 */
const downloadSingleFileHandler = async (connectionOpts, connectionKey, res, remotePath, stats) => {
	let interval;

	try {
		if (!stats.isFile) {
			throw new Error(`Not a file: ${remotePath}`);
		}

		// Force the creation of the session and throw an error if it fails
		const session = await getSession(res, connectionOpts, connectionKey, true);

		if (!session) {
			throw new Error('Failed to create session');
		}

		const host = connectionOpts.host;
		const port = connectionOpts.port;
		const username = connectionOpts.username;
		const address = `${username}@${host}:${port}`;

		const connection = sftpConnections.getConnection(connectionKey);

		// Continuously update the session activity
		interval = setInterval(() => {
			connection.updateLastSessionActivity();
		}, 1000 * 1);

		/** When the response closes, ends the session */
		const handleClose = () => {
			clearInterval(interval);
			connection.closeSession();
		};

		// On response close, end the session
		res.on('end', handleClose);
		res.on('close', handleClose);
		res.on('error', handleClose);

		// Set response headers
		res.setHeader('Content-Type', mime.getType(remotePath) || 'application/octet-stream');
		res.setHeader('Content-Disposition', `attachment; filename="${path.basename(remotePath)}"`);
		res.setHeader('Content-Length', stats.size);

		// Start the download
		console.log(`Starting download: ${address} ${remotePath}`);
		await session.get(remotePath, res);

		// Force-end the response
		res.end();
	} catch (error) {
		// On error, clear the interval and send a 400 response
		clearInterval(interval);
		res.status(400).end();
	}
};

/**
 * Handles the downloading of multiple files from a remote server, compressing them into a zip archive.
 *
 * @param {Object} connectionOpts - The connection options for the remote server.
 * @param {string} connectionKey - The key of the connection.
 * @param {Object} res - The HTTP response object.
 * @param {string[]} remotePaths - An array of remote file paths to download.
 * @param {string} [rootPath='/'] - The root path to use for normalization.
 * @returns {Promise<void>} - A promise that resolves when the operation is complete.
 */
const downloadMultiFileHandler = async (connectionOpts, connectionKey, res, remotePaths, rootPath = '/') => {
	rootPath = normalizeRemotePath(rootPath);
	let interval;

	try {
		// Create the session and throw an error if it fails
		const session = await getSession(res, connectionOpts, connectionKey, true);

		if (!session) {
			throw new Error('Failed to create session');
		}

		const host = connectionOpts.host;
		const port = connectionOpts.port;
		const username = connectionOpts.username;
		const address = `${username}@${host}:${port}`;

		const connection = sftpConnections.getConnection(connectionKey);

		// Continuously update the session activity
		setInterval(() => {
			connection.updateLastSessionActivity();
		}, 1000 * 1);

		// Set response headers
		let fileName = `Files (${path.basename(rootPath) || 'Root'})`;

		if (remotePaths.length == 1) {
			fileName = path.basename(remotePaths[0]);
		}

		res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}.zip"`);

		// Create the zip archive and start piping to the response
		const archive = archiver('zip');
		archive.pipe(res);

		/** When the response closes, end the session */
		const handleClose = () => {
			clearInterval(interval);
			archive.end();
			console.log(`Closing download session`);
			connection.closeSession();
		};

		// On response close, end the session
		res.on('end', handleClose);
		res.on('close', handleClose);
		res.on('error', handleClose);

		/** Adds a file to the zip archive */
		const addToArchive = async (remotePath) => {
			const archivePath = normalizeRemotePath(remotePath.replace(rootPath, ''));
			console.log(`Zipping: ${address} ${remotePath}`);

			// Get file read stream
			const stream = session.createReadStream(remotePath);

			/** Waits for the operation to end */
			const waitToEnd = new Promise(resolve => {
				stream.on('end', resolve);
			});

			// Add file to archive
			archive.append(stream, {
				name: archivePath
			});

			await waitToEnd;
		};

		/** Recurse through directories and archive files */
		const recurse = async (remotePath) => {
			try {
				const stats = await session.stat(remotePath);
				if (stats.isFile) {
					await addToArchive(remotePath);
				} else if (stats.isDirectory) {
					const list = await session.list(remotePath);
					for (const item of list) {
						const subPath = `${remotePath}/${item.name}`;
						if (item.type === '-') {
							await addToArchive(subPath);
						} else {
							await recurse(subPath);
						}
					}
				}
			} catch (error) { }
		};

		for (const remotePath of remotePaths) {
			await recurse(remotePath);
		}

		// Finalize the archive
		archive.on('close', () => res.end());
		archive.finalize();
	} catch (error) {
		clearInterval(interval);
		res.status(400).end();
	}
};

//============================//
//        DOWNLOAD API        //
//============================//


// Download a single file from the SFTP server
srv.get('/api/sftp/files/get/single', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;

	// Get the normalized path and throw an error if it's missing
	const remotePath = normalizeRemotePath(req.query.path);
	if (!remotePath) {
		return res.sendError('Missing path', 400);
	}

	try {
		// Get the file metadata and download it
		const stats = await session.stat(remotePath);
		await downloadSingleFileHandler(req.connectionOpts, req.connectionKey, res, remotePath, stats);
	} catch (error) {
		res.status(400).end();
	}
});

/** Stores the raw download handlers */
const rawDownloads = {};

// Download a single file from the SFTP server and get a URL
srv.get('/api/sftp/files/get/single/url', initApi, async (req, res) => {
	/** Obtained in `initApi` @type {sftp} */
	const session = req.session;

	// Get the normalized path and throw an error if it's missing
	res.data.path = normalizeRemotePath(req.query.path);
	if (!res.data.path) {
		return res.sendError('Missing path', 400);
	}

	// Get path stats and throw an error if it's not a file
	let stats = null;
	try {
		stats = await session.stat(res.data.path);
		if (!stats?.isFile) throw new Error('Not a file');
	} catch (error) {
		return res.sendError(error);
	}

	// Generate download URL
	const id = utils.randomHex(8);
	res.data.download_url = `http://${req.get('host')}/dl/${id}`;

	// Create download handler
	rawDownloads[id] = {
		created: Date.now(),
		paths: [res.data.path],
		handler: async (req2, res2) => {
			await downloadSingleFileHandler(req.connectionOpts, req.connectionKey, res2, res.data.path, stats);
		}
	}
	res.sendData();
});

// Download multiple files from the SFTP server and get a URL
srv.get('/api/sftp/files/get/multi/url', initApi, async (req, res) => {
	try {
		// Get the normalized path and throw an error if it's missing
		res.data.paths = JSON.parse(req.query.paths);
		if (!res.data.paths) {
			throw new Error('Missing path(s)');
		}
	} catch (error) {
		return res.sendError(error);
	}
	console.log("[Multi url] Passed first try")

	// Generate download URL
	const id = utils.randomHex(8);
	res.data.download_url = `http://${req.get('host')}/dl/${id}`;

	// Create download handler
	rawDownloads[id] = {
		created: Date.now(),
		paths: res.data.paths,
		isZip: true,
		handler: async (req2, res2) => {
			await downloadMultiFileHandler(req.connectionOpts, req.connectionKey, res2, res.data.paths, req.query.rootPath);
		}
	}
	console.log("[Multi url] Created download handler")
	res.sendData();
});

// Process download requests
srv.get('/dl/:id', async (req, res) => {
	/** Download handler */
	const entry = rawDownloads[req.params.id];

	if (!entry) {
		return res.status(404).end();
	}

	// If the user agent looks like a bot
	if (req.get('user-agent').match(/(bot|scrape)/)) {
		// Send some HTML
		res.setHeader('Content-Type', 'text/html');
		const html = /*html*/`
			<html>
				<head>
					<title>Download shared files</title>
					<meta property="og:site_name" content="SFTP Browser" />
					<meta property="og:title" content="Shared ${entry.isZip ? 'files' : 'file'}" />
					<meta property="og:description" content="Click to download ${entry.isZip ? `these files compressed into a zip.` : `${path.basename(entry.paths[0])}.`} This link will expire on ${dayjs(entry.created + (1000 * 60 * 60 * 24)).format('YYYY-MM-DD [at] hh:mm:ss ([GMT]Z)')}." />
					<meta name="theme-color" content="#1f2733">
					<meta property="og:image" content="https://${req.get('host')}/icon.png" />
				</head>
				<body>
					<p>Click <a href="${req.originalUrl}">here</a> to download the file.</p>
				</body>
			</html>
		`;
		res.send(html);
	} else {
		entry.handler(req, res);
	}
});

//============================//
//           OTHER            //
//============================//

// Error for non-existent API routes
srv.use((req, res) => res.status(404).end());

// Delete inactive sessions and downloads
setInterval(() => {
	//console.log(`-----------Deletion interval start, connections=${Object.keys(sessions).length}`)
	const maxTimePassed = 1000 * 60 * 5;
	const downloadMaxTimePassed = 1000 * 60 * 60 * 12;

	// Inactive sessions
	for (const connection of sftpConnections.getAllConnections()) {
		const key = connection.key;
		const lastActive = connection.lastSessionActivity;
		const credentialsCreation = connection.credentialsCreationTime;
		const now = Date.now();
		const timePassedSinceLastActive = now - lastActive;
		const timePassedSinceCredentialsCreation = now - credentialsCreation;

		if (!lastActive) {
			// If the session was never active, check the credentials creation time
			if (timePassedSinceCredentialsCreation > maxTimePassed) {
				console.log(`Deleting inactive connection with only credentials '${key}'`);
				sftpConnections.removeConnection(key);
			}
			continue;
		}

		// console.log(`[connection deletion] connection: ${hash}`)
		// console.log(`[connection deletion] lastActive: ${Date(lastActive)}`)
		// console.log(`[connection deletion] difference in time: ${(time_passed_since_last_active)/1000}s`)
		// console.log(`[connection deletion] tolerance: ${max_time_passed/1000}s`)
		
		if (timePassedSinceLastActive > maxTimePassed) {
			console.log(`Deleting inactive connection '${key}'`);
			sftpConnections.removeConnection(connection.key);
		}
	}


	// Unused downloads
	for (const id in rawDownloads) {
		const download = rawDownloads[id];
		if ((Date.now() - download.created) > downloadMaxTimePassed) {
			console.log(`Deleting unused download`);
			delete rawDownloads[id];
		}
	}
}, 1000 * 30);

// Do not make the server crash on uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('================');
    console.error('Uncaught Exception found');
	console.error(err);
	console.error('================');
});


//============================//
//          ELECTRON          //
//============================//

if (Electron.app) {
	Electron.app.whenReady().then(async () => {
		// Start the server
		let port = 8001 + Math.floor(Math.random() * 999);
		await new Promise(resolve => {
			srv.listen(port, () => {
				console.log(`App server listening on port ${port}`)
				resolve();
			});
		});
		// Open the window
		const window = new Electron.BrowserWindow({
			width: 1100,
			height: 720,
			autoHideMenuBar: true,
			minWidth: 320,
			minHeight: 200
		});
		window.loadURL(`http://localhost:${port}`);
		// Quit the app when all windows are closed
		// unless we're on macOS
		Electron.app.on('window-all-closed', () => {
			if (process.platform !== 'darwin') Electron.app.quit();
		});
	});
} else {
	srv.listen(config.port, () => console.log(`Standalone server listening on http://localhost:${config.port}`));
}