//@ts-check

// This script will be run within the webview itself
// It cannot access the main VS Code APIs directly.
(function () {
    const vscode = acquireVsCodeApi();

    /** @type {Array<{ value: string }>} */
    let selected = null;

    document.querySelectorAll('div.text-container > div').forEach((element) => {
        element.addEventListener('click', (e) => {
            vscode.postMessage({ type: 'packetSelected', value: e.target.id});
            if(selected !== null) {
                selected.classList.toggle(`active`);
            }
            e.target.classList.toggle(`active`);
            selected = e.target;
        });
    });
}());

window.addEventListener('message', event => {
    const message = event.data; 
    switch (message.command) {
        case 'customevent':
            let idx = 0;
            let lastid = 0;
            document.querySelectorAll('div.text-container > div').forEach((element) => {
                if (message.data.length === 0) {
                    element.classList.remove(`highlight`);
                    element.style.display = 'block';
                } else {
                    if (element.id === lastid) {
                        idx--;
                    }

                    if (message.data[idx] === Number(element.id)) {
                        idx += 1;
                        lastid = element.id;
                        if (!message.filterMode) {
                            element.classList.add(`highlight`);
                        } else {
                            element.classList.remove(`highlight`);
                        }
                        element.style.display = 'block';
                    } else {
                        if (message.filterMode) {
                            element.style.display = 'none';  
                        } else {
                            element.classList.remove(`highlight`);
                            element.style.display = 'block';
                        }
                    }
                }
            });
            break;
    }
});



