if (typeof window.ethereum !== 'undefined') {
    console.log('MetaMask доступен!');

    const connectButton = document.querySelector('.wallet__connect-button');
    const accountParagraph = document.querySelector('.wallet__account');

    // Обработка подключения MetaMask
    connectButton.addEventListener('click', async () => {
        try {
            // Запрос на доступ к аккаунту
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const account = accounts[0];
            accountParagraph.innerText = `Адрес: ${account}`;
        } catch (error) {
            console.error('Ошибка подключения:', error);
        }
    });
} else {
    console.log('Установите MetaMask!');
}

const hashButton = document.querySelector('.hasher__hash-button');
const hashInput = document.querySelector('.hasher__input');
const hashResult = document.querySelector('.hasher__hash');

// Функция для получения SHA-256
async function getSHA256Hash(message) {
    const msgBuffer = new TextEncoder().encode(message);                    
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Обработка нажатия кнопки для хэширования
hashButton.addEventListener('click', async () => {
    const text = hashInput.value;
    if (text) {
        const hash = await getSHA256Hash(text);
        hashResult.innerText = hash;
    } else {
        hashResult.innerText = 'Введите текст!';
    }
});
// // Док панель
// const dockItems = document.querySelectorAll('.dock__item');
// const iframe = document.querySelector('.dock__iframe');

// dockItems.forEach(item => {
//     item.addEventListener('click', () => {
//         const url = item.getAttribute('data-url');
//         iframe.src = url;
//     });
// });


document.addEventListener('DOMContentLoaded', () => {
    // Адаптация ключа для AES шифрования/расшифровки
    async function adaptKey(key, length) {
        const enc = new TextEncoder();
        let keyArray = enc.encode(key);

        // Если ключ слишком короткий, дополняем его нулями
        if (keyArray.length < length) {
            const paddedArray = new Uint8Array(length);
            paddedArray.set(keyArray);
            keyArray = paddedArray;
        }
        
        // Если ключ слишком длинный, обрезаем его
        if (keyArray.length > length) {
            keyArray = keyArray.slice(0, length);
        }
        
        return keyArray;
    }

    // Адаптация IV
    function adaptIV(iv) {
        const ivArray = new Uint8Array(16);
        const ivBuffer = new Uint8Array(iv);

        // Если IV слишком короткий, дополняем его нулями
        if (ivBuffer.length < ivArray.length) {
            ivArray.set(ivBuffer);
        } else {
            // Если IV слишком длинный, обрезаем его
            ivArray.set(ivBuffer.slice(0, ivArray.length));
        }

        return ivArray;
    }

    // Генерация случайного ключа
    function generateRandomKey(length = 32) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // Генерация случайного IV
    function generateRandomIV(length = 16) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // AES шифрование
    const aesEncryptButton = document.querySelector('.aes-encryptor__encrypt-button');
    const aesInput = document.querySelector('.aes-encryptor__input');
    const aesKeyInput = document.querySelector('#encrypt-key');
    const aesResult = document.querySelector('.aes-encryptor__encrypted');
    const aesGenerateKeyButton = document.querySelector('#generate-encrypt-key');

    async function encryptText(text, key) {
        const keyBuffer = await crypto.subtle.importKey(
            'raw', 
            await adaptKey(key, 32), // AES-256 требует 32 байта (256 бит)
            { name: 'AES-CBC' }, 
            false, 
            ['encrypt']
        );
        const iv = generateRandomIV(); // Генерируем случайный IV
        const enc = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv },
            keyBuffer,
            enc.encode(text)
        );
        return {
            iv: Array.from(iv),
            encrypted: Array.from(new Uint8Array(encrypted))
        };
    }

    aesEncryptButton.addEventListener('click', async () => {
        const text = aesInput.value;
        const key = aesKeyInput.value;
        if (text && key) {
            try {
                const encryptedData = await encryptText(text, key);
                aesResult.innerText = `Encrypted: ${JSON.stringify(encryptedData.encrypted)}, IV: ${JSON.stringify(encryptedData.iv)}`;
            } catch (e) {
                console.error('Ошибка шифрования:', e);
                aesResult.innerText = 'Ошибка шифрования. Проверьте ключ и текст.';
            }
        } else {
            aesResult.innerText = 'Введите текст и ключ!';
        }
    });

    aesGenerateKeyButton.addEventListener('click', () => {
        const randomKey = generateRandomKey(); // Генерируем случайный ключ
        aesKeyInput.value = Array.from(randomKey).map(b => String.fromCharCode(b)).join(''); // Преобразуем ключ в строку
    });

    // AES расшифровка
    const aesDecryptButton = document.querySelector('.aes-decryptor__decrypt-button');
    const aesDecryptInput = document.querySelector('.aes-decryptor__input');
    const aesDecryptKeyInput = document.querySelector('#decrypt-key');
    const aesDecryptIvInput = document.querySelector('#decrypt-iv');
    const aesDecryptResult = document.querySelector('.aes-decryptor__decrypted');

    async function decryptText(encrypted, key, iv) {
        try {
            console.log('Исходные данные для расшифровки:', {
                encrypted,
                key,
                iv
            });

            // Адаптируем ключ и IV
            const keyBuffer = await crypto.subtle.importKey(
                'raw',
                await adaptKey(key, 32), // AES-256 ключ 32 байта
                { name: 'AES-CBC' },
                false,
                ['decrypt']
            );
            const ivBuffer = adaptIV(iv);
            const encryptedBuffer = new Uint8Array(encrypted);

            console.log('Ключ после адаптации:', keyBuffer);
            console.log('IV после адаптации:', ivBuffer);
            console.log('Зашифрованный текст после преобразования в Uint8Array:', encryptedBuffer);

            // Попробуем расшифровать
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: ivBuffer },
                keyBuffer,
                encryptedBuffer
            );

            const dec = new TextDecoder();
            return dec.decode(decrypted);
        } catch (e) {
            console.error('Ошибка расшифровки:', e);
            throw e; // Пробрасываем исключение для отображения ошибки в UI
        }
    }

    aesDecryptButton.addEventListener('click', async () => {
        try {
            const encryptedText = JSON.parse(aesDecryptInput.value || '[]');
            const key = aesDecryptKeyInput.value;
            const iv = JSON.parse(aesDecryptIvInput.value || '[]');

            console.log('Данные для расшифровки:', {
                encryptedText,
                key,
                iv
            });

            if (encryptedText.length && key && iv.length) {
                const decryptedText = await decryptText(encryptedText, key, iv);
                aesDecryptResult.innerText = decryptedText;
            } else {
                aesDecryptResult.innerText = 'Введите зашифрованный текст, ключ и IV!';
            }
        } catch (e) {
            aesDecryptResult.innerText = 'Ошибка расшифровки. Проверьте данные.';
        }
    });
});

 // Загрузка списка приложений из JSON файла
 async function loadApps() {
    try {
        const response = await fetch('apps.json');
        if (!response.ok) throw new Error('Ошибка загрузки данных');
        const apps = await response.json();

        const appList = document.querySelector('#app-list');
        appList.innerHTML = '';

        apps.forEach(app => {
            const listItem = document.createElement('li');
            listItem.textContent = app.name;
            listItem.addEventListener('click', () => {
                document.querySelector('#app-frame').src = app.url;
            });
            appList.appendChild(listItem);
        });
    } catch (error) {
        console.error('Ошибка при загрузке списка приложений:', error);
    }
}
loadApps();

function getProvider(network) {
    switch (network) {
        case 'kovan':
            return new Web3(new Web3.providers.HttpProvider('https://kovan.infura.io/v3/YOUR_INFURA_PROJECT_ID'));
        case 'polygon':
            return new Web3(new Web3.providers.HttpProvider('https://polygon-rpc.com/'));
        default:
            throw new Error('Unsupported network');
    }
}

// Проверка баланса
const checkBalanceButton = document.querySelector('#check-balance');
const walletAddressInput = document.querySelector('#wallet-address');
const networkSelect = document.querySelector('#network');
const balanceDiv = document.querySelector('#balance');

checkBalanceButton.addEventListener('click', async () => {
    const address = walletAddressInput.value;
    const network = networkSelect.value;

    if (!Web3.utils.isAddress(address)) {
        balanceDiv.innerText = 'Введите действительный адрес кошелька!';
        return;
    }

    try {
        const web3 = getProvider(network);
        const balance = await web3.eth.getBalance(address);
        const balanceInEther = web3.utils.fromWei(balance, 'ether');
        balanceDiv.innerText = `Баланс: ${balanceInEther} ${network === 'kovan' ? 'ETH' : 'MATIC'}`;
    } catch (error) {
        console.error('Ошибка при получении баланса:', error);
        balanceDiv.innerText = 'Ошибка при получении баланса.';
    }
});