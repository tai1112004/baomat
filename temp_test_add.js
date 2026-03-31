const http = require('http');
const doPost = (path, data, token) => new Promise((resolve, reject) => {
  const s = JSON.stringify(data);
  const opts = { hostname: 'localhost', port: 3000, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) } };
  if (token) opts.headers['x-auth-token'] = token;
  const req = http.request(opts, res => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => resolve({ status: res.statusCode, body: d }));
  });
  req.on('error', reject);
  req.write(s);
  req.end();
});
(async () => {
  try {
    const login = await doPost('/api/login', { username: 'khachhang', password: 'khachhang' });
    console.log('LOGIN', login);
    const token = JSON.parse(login.body).token;
    const add = await doPost('/api/users/add', { full_name: 'Test KH', email: 'a@b.com', phone: '0900000000', cccd: '123456789012', salary: 1000000, birth_date: '2000-01-01', address: 'Hanoi' }, token);
    console.log('ADD', add);
  } catch (e) {
    console.error(e);
  }
})();