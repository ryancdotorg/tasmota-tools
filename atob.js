const atob = a => String.fromCharCode.apply(null, Buffer.from(a, 'base64'));
