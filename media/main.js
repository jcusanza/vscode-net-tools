//@ts-check

// This script will be run within the webview itself
// It cannot access the main VS Code APIs directly.


function drawMinimap() {
    var style = window.getComputedStyle(document.body);
    const allRows = document.querySelectorAll('div.text-container > div');

    const canvasc = document.getElementById("mmc");
    const canvas = document.getElementById("mm");

    canvas.height = canvasc.clientHeight;
    const mult = canvas.height / allRows.length;

    const ctx = canvas.getContext("2d");
    ctx.lineWidth = mult > 3 ? mult : 3;
    ctx.strokeStyle = style.getPropertyValue('--vscode-editor-findMatchHighlightBackground');
    ctx.clearRect(0,0,5,canvas.height);

    let row = 1;
    allRows.forEach((element) => {
        let draw = false;

        if (element.classList.contains(`active`)) {
            ctx.strokeStyle = style.getPropertyValue('--vscode-list-activeSelectionBackground');
            draw = true;
        } else if (element.classList.contains(`highlight`)) {
            ctx.strokeStyle = style.getPropertyValue('--vscode-editor-findMatchHighlightBackground');
            draw = true;
        } else if (element.classList.contains(`comment`)) {
            ctx.strokeStyle = "#009200";
            draw = true;
        }

        if (draw) {
            ctx.beginPath();
            ctx.moveTo(0, row*mult);
            ctx.lineTo(5, row*mult);
            ctx.stroke();
        }
        row += 1;
    });
}

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
            drawMinimap();
        });
    });

    drawMinimap();
}());

window.addEventListener('resize', event => {
    drawMinimap();
});

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
            drawMinimap();
            break;
    }
});



