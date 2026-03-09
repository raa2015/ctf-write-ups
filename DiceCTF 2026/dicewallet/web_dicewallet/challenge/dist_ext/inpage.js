(() => {
  if (window.ethereum) return;
  if (!["http:", "https:"].includes(location.protocol)) return;
  const secret = document.currentScript?.getAttribute("data-secret");
  if (!secret) return;
  document.currentScript.remove();
  let requestId = 0;
  const pending = /* @__PURE__ */ new Map();
  const listeners = {};
  const provider = {
    isDiceWallet: true,
    isMetaMask: true,
    chainId: null,
    networkVersion: null,
    selectedAddress: null,
    async request({ method, params }) {
      return new Promise((resolve, reject) => {
        const id = ++requestId;
        pending.set(id, { resolve, reject });
        window.postMessage({ type: "DICE_REQUEST", id, method, params }, location.origin);
      });
    },
    async enable() {
      return provider.request({ method: "eth_requestAccounts" });
    },
    async send(methodOrPayload, paramsOrCallback) {
      if (typeof methodOrPayload === "string") {
        return provider.request({ method: methodOrPayload, params: paramsOrCallback });
      }
      try {
        const result = await provider.request(methodOrPayload);
        if (typeof paramsOrCallback === "function") paramsOrCallback(null, { result });
        return { result };
      } catch (err) {
        if (typeof paramsOrCallback === "function") paramsOrCallback(err);
        throw err;
      }
    },
    sendAsync(payload, callback) {
      provider.request(payload).then((result) => callback(null, { id: payload.id, jsonrpc: "2.0", result })).catch((err) => callback(err));
    },
    on(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push(fn);
      return provider;
    },
    removeListener(event, fn) {
      listeners[event] = (listeners[event] || []).filter((f) => f !== fn);
      return provider;
    },
    removeAllListeners(event) {
      if (event) delete listeners[event];
      else Object.keys(listeners).forEach((k) => delete listeners[k]);
      return provider;
    }
  };
  window.addEventListener("message", (e) => {
    if (e.origin !== location.origin) return;
    if (e.data?.secret !== secret) return;
    const data = e.data;
    if (typeof window[data.fn] === "function") {
      window[data.fn](data);
    }
  });
  window.dwOnMessage = function(data) {
    const p = pending.get(data.id);
    if (!p) return;
    pending.delete(data.id);
    if (Array.isArray(data.result) && data.result.length > 0 && data.result[0]?.startsWith?.("0x")) {
      provider.selectedAddress = data.result[0];
    }
    p.resolve(data.result);
  };
  window.dwOnError = function(data) {
    const p = pending.get(data.id);
    if (!p) return;
    pending.delete(data.id);
    p.reject(new Error(data.error));
  };
  provider.request({ method: "eth_chainId" }).then((chainId) => {
    provider.chainId = chainId;
    provider.networkVersion = String(parseInt(chainId, 16));
  }).catch(() => {
  });
  const info = {
    uuid: "dice-wallet-" + Math.random().toString(36).slice(2),
    name: "DiceWallet",
    icon: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAeGVYSWZNTQAqAAAACAAEARoABQAAAAEAAAA+ARsABQAAAAEAAABGASgAAwAAAAEAAgAAh2kABAAAAAEAAABOAAAAAAAAAEgAAAABAAAASAAAAAEAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAgKADAAQAAAABAAAAgAAAAAB7ATBAAAAACXBIWXMAAAsTAAALEwEAmpwYAAAXpUlEQVR4Ae2dbawdxXnH97772tc2xm/guoTIkFi2wb5YgVK1xYmpIkSSqkIIKZESK2kiiFSUkkhRv/QDNCKVWrVB5MVRoYqKEEqURiHth3xIoIkSS8U2vjY3icE2xtgGG79y7fvme+7t/zd353jP3p1z9szZc87e4/NIe3Z3duaZmef5z/PMzM7O6QhyTFu2bNnZ2dn5penp6ZpL2dHREczMzBzp6uq6bc+ePaM1M2wRBp0tUo92NTwl0AaAp+BaJVl3zisyFS3flMx4QQEd0cDINeE9MzORkNJLuYGZtvmPyaT0trl3g4ODn1IJ1oQ+f0b+/zO6/3P5bqP49VeuBGt1AII4YcrOdXUFQ319iQAJ+wBndH5C/CcU3YWjOOuG3au+gcp2emho6L8alWmuLIAq//fd3d1/grIgFM8BFRR21+hosP3y5WAyfG4ehD/dije8YEGwT0dHmCb6POSzQry/pY5g9FFursN671eBrk0ASADjtH6r9LhmcAEoPwkAjBOuJAAjzgP+eSUAoLqPN7J8ubIAEkCJdUfhVl0o3V67BMRz4tWzZ4ulqSd/yaBSNV3V9wpvKgA0zr9fFb5BJTd2XuhfSyuAkML6yclgDT5fYSBjzdSUEwTEX1YoBB+Ti6iXc0fxw729wRm5kHqBQDJYrb7Q55VVVtRRKBR+uX///jeTGDYVAKrsP8gf36mzKRtne03r/1P5/I9GfD5hHEk0rfAbBZDPXbiQ9DiTMFr/t5YvD051dwedYZkzYRwyCev+QTWCZ7LiS8dS9Gkd+QOACjXh6/OpVZysC4iHZ3UPf456U9b9FPErca3R8jfVAgjpJfKklLRk2jgdupKH0VI38ZoyUrZkO1RbwbCD8MXSNIrqBoBt27Z1nzt3bqtMfJ8UnVgjIXNZtKI3y4QvZBSgQEz9svA6GqeZ15TrJpVxYmKiLkpC+eOq91s9PQ2rZt0AcOHChQH5n59I+TeWM2nW5yPcB99/P/iwhGv9PGFphnaNkhad0U+NjNQtO1r+m+pk/pP6GdS9EVQ3AISFn7YKTlMZ62PzaPpt+etZNlt/m1cjznUDQH9//8TY2FgJkG3LTqoYEUsiJ0XKOkwtblrDTA09nJw71SIDtXwXzcglzGj46Usd6qV3REw+JUFO0RLVs0+QGQDuvvvu/vHx8S1q8UZao6OjAzL/fVYwDEbWaVyPd4tWzj4nrF+KSHpm42R6Vl6dmjZefNddAUpIJMW5dOBAMK2haBIIZtRH6b/11qD3Bk1llAFRIu8wsCDel5UHRN0XiM+HJSeuESRvw94WQPwhJgZlKDMAqGN0s5T/K+VleEr5JltcAJXp0/mLGqMvV2txmVHC8bONIFptz+rVwaYf/SjoopUnEGV/9d57g8tDQyWt1EadVn9lzcMPB2s++1kbVPV5RMof+vjHNfyZNnVfJYvyd2fPGj7A8qLA+cSKFcGIzg6YVp1nNEFmAAiZlm3APGyGn4tWeM51OfPNM4GgLElxNVFC+ijHCrnXlDWJMwOAphvVeEuHe7YiVvHVlhYTS8sw5leKMKbaZa6TmCuN8c8JVqVW352UnU9YkvuxLZ2zvS7H28rZxsGGprWj3gDYtm3bAo3zVxQz7ehYE82XAlwv5VEBCoh/T1MZRZ0lxe+5/vqga9Gi2VYoJU5dvBgUGIYlKNQmK57Jr78/6NGQKqkVA4y+NSpyGl5FptVfFMbHTbmtS4xzmDxzpiQIF/h+CHJkeEnXlazAdZIzHcUZpeVVOGkmuC7hnHzjDYDz58//hSZ5foifDAn9mhkMFD6g8EfPnQuuk6AtQnsVZq9tItd5WoK76etfD1Y/+GARAG9+4xvBiW9/O+hauNCVrBiOf156zz3BhmefTQSAiShBdakjWE86+/OfB4e+8pWgUwtVkshYKGQohaHEE+rwPSXgI1UUyJnJoaTGwzNWNnxJfas/ChfKoIBnr7sueEX1Qt6VyBsAQjR5LS2XAT1aDqv0ysUp5UYv3ViAMLjD0VkrTXX1rkMvbaLprz5p3NWMgHhFnTqsURKZVhq2eJ4jq1EpPCqrSi2ZDvYCWQGsB0viunSkpVoAYPVazMtmyzl+FCNFLyioq7D4fo4oueJG40Svq40fTcu1BFqRKsWRcs1YP6JkF1fC7RHN18o1GsZ1XMb2Ph6v3H01AOi85ZZbjInv6xPmZmZ6o36NgtsFmagtjfnpUAtP6gSZAiM4teCaSAAomlgPRmnSEscZj5bMSCJCKKncUDf+LCrXCBtzCS9cAHF8KbWEtUjho8rkaeb16e3rkJunCKqQjhtVUXwR5odQfNaA4sbasEJFpJNwPvSd7wQDGzcmWgF4965cORvf4xefO/LKK2Yc75HcJKEME0ePOoHYpTyOP/VUcOq55xLrQB2nJBNcGUQD2SdX8OPFixNfJqFIVjTNSnXWHdDBe1g8+nW24YZZ5IeFMHHgRB6XvUwNACl+iTp968MFBnOY0oG5QZMYFgAUNlH5kZQL1q4N+j/wgUhIhpcSZOHSpeIsmy9nY4XEK5FkpSZPngwmjx9PfGwCsWThIlS4jInX27Js1lomJYwuWaUhrZZc7VvSpPilNiYphjssNQCk+AItwrb6JJYonEq6kBpPY8b58cAs7yXs6Dx7lqwtL6PcCquMLXw4c6DgqJLj8rL3nDlQMIcN12VmVA4AnVu3bi2WU4pXIy9fBINECd3EUtykoUu05MZ/yrSlpgr5p+bTwIjIgkUuUJISeeJSApJxPYNfFuTkv3nz5h1S+Fdl+q3WF7syRNHvqRX8M5MuIgq+UMpi7n+x/NMcFYcCeePRR4POFGN6w1Q/k++8U/dxu80rizNm/lX5/J/I53ONsi+r7rhLCL/9QY3fd0hOc2RkYsxaCoZ4VglhcGYnJwCUwyp19DboKGbmsgDEoPNyLOy1UxkmgoxFKKaeezH2+uvJnae5UWdDBDLnqMGVponhVuGs8OnF0klGzNRZy4hSGS2x8tkFANJUkmMtVXQCQIo3izlcSo9nSmWtv4hex+NF72se5kWZ5fTayEJKNrLROU6EYAmcAIgnyPjeCYAs8sHUcfhUDsE1UzC+9ad125EQZt82CsvPKpx7Fn74Dt8sv1rPdQEAyuNlxA80J40Q5uK+crERDh95bORliq7nAwH2XerT7Jbf5xownJXb4hqiHps0NfyXqhcLPXh5s0iuwaeBGIYZ/NQNAPgtvtT1JfoUt0v51l/68mlkOsp6Qv2g6IsYaxEoB4pmQczg2Fjx+0ag0UyA1wUAVBai9fsSKeeT8m09MfnU21V3QMBK57ysdvYGAArK2n/hO6PG3grTH0ZWLcln+Nba+iij/UwMpcdBG5UTeTXT3CdJwQsAVIQFnvdrqjUrECC4FwcGgmMaMgEE/Ob/yp/+Xq+A7URKUgV8w1DEEvnfv9a3CCjOB2TG52vByj65OgQJEI6r/FGff5t8Pn0Zq3xcQK2g861zUjovACAsXlLcIV+WVWVoSS9J4SjGtCqd35Q/PSSBRq2CgjMh+iirpIy/qoEboGXu47fq9PFOHrkAXsoPUZcVymNrxOcTllWjIY9ayQsAZEpF8GNZAQB+8VaIIBFoPQjeLj9dTX7wYTLHxcvKKS8+P143bwDEGWVxj5AYPvqonDS0SJciksqHZUF5HD550upta7f8aRBYF3hTl0oNhPchLF+zxEynfX1sw+p5zg0AaCnbtB8A42Tbqaqm4ij/tMzxr2WO07gM4lyWsF/k3byufQCAdXoj7LNQVkz7oIaufNjBOJ/7m1irp3MSsTJ5wbp1wY07dsw+VrwJvV5+5/vfn50id6RL4uUblhsAoIA7BQAU6aMMWv5rWnjxK/UjkjaJigsIlbD27n/U8fQlykmHz1oBWv4GAfg+dY7tqlzCXFaA1s+aiLX6uMTSZb0fMQCwAXU+5wYA1LMWP2l9bTXyAgSY/ywJZaN8JrLSUHxNBKuhG0m5AkCtFQcECN+2yGr4AQNUhiVJp7p03DHz03IJSYSyG63weDlaBgDMFfBdHXsM+CiQNJhr5h74MANXVCvNyP8v/shHguX33Tfr02MMcQF99VoSF8vLdds6AFANGXOzgYOPUUfhmO096kRedEmrynAAMDA4GPyxFr7klVoGAAjYugAfYWMB6IP4gKdcfriAPFNLASALQQMCLIGrH0GvPwv3kEVZs+DRBkBEiliBreqYrXP0ARhe/kHz/ucczyOs5s1lGwChqjD9TOw8oC+QAUKSK2CEwEaR72m+wWeyKo+oaAMgppVycxGAgn5GK1ErubOW0EujF8q2LUCTYVPQq+Kxw4dnS6HOJ1PBjaQ2ABop7YS8RqXwofvvl2+Rc1Hnsvi5vMDQCGoDoBFSrpSHJrAMAAAB1CDlk1UbAEihiVT8+hilN1DxtsptAFhJNOjMRlfj9nNyKRwX0ExqA6DB0j/38svBH77whdJNozS/0IzWT9XbAGgwAEwnj/cDWr1UpCaYfpt3pBQ2qH3OVAJx5dLTJywenmmm6Zm1AZBeVtXHlJJZ8HFF3/+blq/71BtdVp+bV4o2ALzEli4Rq3vPvvhicOGll4oAABBmC/p0LOoeqw2AeooYC6CZPraEt2Q23MAN5IRSA4AXIRwQ0xX22gRk9GMWSNIjdpDZHSQnvtNRxLnBKq/dJWzuw+aHpAYAr0LZ8BnijRl7AGVNbA5tdvVK4q082fZtWkvH89KByrr+zeCXCgAofJNWtu44f96scUf1JHStd/epCK3/1qefDpZs3TrrL+NMVIaj3/xmcPJ73wu6tG6vTdlIIBUAyAoLwNe09n05IMjaBvQsXRr0aFcRF5lPppKsgytBO7yiBFIDAGXj+8PXFRUZ+0SIfyQxhwcvSwBAORDIUrQclasvla2hzqkBkAuh0ntmBs21M2clcOSiEh6FcNXXsrJvEe19Fed5BYC1jzwy+wcSSRVUKxjZuzc49Nhjue51JxXdFYZF7F21KlivP70o/nNKNDItX6A/+OUvB6PDw17b4s4rAPTpX744XFTQV0Fl3YMrYV7DpVz+JGPgttvK7pBq/oyikptw1DE/MxKOAlYTnPePMFLXxboyzrICfGHkIrORp6fy4TmvLIBLCC0VjlmPzhRW8v81Vr4NgBoFmGVyWvqi228PPqQ/oYAYeXWyAYU+WK0XtQFQL8l68MWc09kb2LTJI7VfkpbqA/iJIGepavDnPjVpKQvAsInXrcWPK+RL8/Tq1UdB9U7TUgBYtGFDsOH554srblhweUzvD+bTfwzUW+Fx/i0FgF79y/bKT36yWMcR/TXssSefLN63L+ZKoKX7AK69eeaK4doNaWkAXAtqrXWFUUu5gGtB4Ux1v/vCC8Hku++avg1zBVd07XxBVkEobQBUEFDeHjNXcFz/uHpp927znoDy8Q/ovsvO2gDIm4ZTlIeFMUwYZfGnmLkCQNabJGfND93YnUAxvRzRrWJ5zj2bSEMsTSm3VayJVOWPGdJG3xVUmT4ePT8A0EuQU/JtF3ftMq902UTx+u3bg0Xr18fL7LwfP3EieE/r8E3HSPzG33qrptUy8YzYjPIuLfNmA2h6z+wp9DttGsV/GrCrGAf3bA4d3Sx6o/YPBgg+VNDEFnJhIwnqhQu4cvp06QsjH8ZhmtwAgMqd/O53A7ssjPX06595pioAjB06FBz+2teKM4FZb73Ocri7Ixta09Kf1xrGg3pnDxg4XpV53o1PVly2rb1X8fnzK9eO4ZV0x0roo48/HkxK6dbP1+Lz4/nlBgAULGqyAURxSjdeasc9AuLNWbXpHOwSg+2iWPsw3rJxAVGhcl8TSQ4s+DD1qsOr4WhZaypnPRJX28lpiXn/mH/vlEuptOgTkGFxIFZvVzO5k1sA0JovDQ0F3fpYxGyfMls/968Ed/m11yoKy82g+U9wWVP69uLsL35RLMyUlrnNsNu4LIGLDsrl8N8HxMANnZfs0oIgvwCQXz25c2dwQv2CtOTjNtLybkQ8XNfYG28Eww89VJIdi0JcL7RwMD9csiQ4ojjW3QACe13CKOEmtwCgrFgB2/FJKHtrBuHzpcxqyCo8rdKjvHMNgGhB29dXJRD1+ViAuHMwljB0GZ1yKxo6uva+LumwXs2hfZVrCbyujuGYFMvm1QBgLPT/ttBS+G4dJ3UYbExPT79tn8XPbQsQl0iO79EmcxEv6BvKo0w+CQAQZ3tN65fi/3Hfvn0/NQ8r/LQBUEFAeXxsfb5VeryMAkFqvaaOGM+kfd84CRgHrlaOBbBHNHdavSWuZfLTjgLbfQAruLyeMfnvaXjI2bqA+GykTP5hPbb/N0c07UqVjtoWIJ2cmhKLZnxJnb1/02QYZ9usmX6OmP+CevoPqeXvt4Xcs2dPfIbaPppzbgNgjkjyF8CbRb4OtAC4avCLZb0ipbs/ICxGm3uRGgBkCup4JZpE9EcxU22qTQJI1yqaMwdh9tDl7OtuLkQy/13V+PzZVFd/UwGAzMel+Hc09HDtC8TkxDK2PW9TTRLAvzOXD6F8TH+sYUnnM0f1aFxnWf6OQldXl/X/Cq6OUgEA5fLO+wmtu08i1L5Wyv/q2bPGSsyOTpNitsPKSQA5H1cj+1f5/KIMBYio+Vf6ghT/wNTU1PDExERHX1/fjMb8XuafsqQCABFBoWtRAwDwLgHM21SUAIrnfwuLANA9FjhGk8PDw8l/SByLWOnWCQDMSzzxnIAwAuHRI54u7X200mnTtEI8K9c0MpRe9I91c3XjKwcnAORb8Cvl/kaXtItsxiiPfgLey1eR1S5msHnP5zOW1Y7ruyU/lpHFCHGO6DBilV6m5PMz62w5ATA2Nvas/MuPY4UxtyrEjMae23XzA6HRKP20JiuedPQRknjEw6jd32gxxDotfnB1NONp5vs9Pv8t9a12LltmqsLLHepuG5DkTC//jHr5H1MEM7mD7HVoVWg25ATAwYMHQR1HIt1xxx2nUL4lIHlWPVZfgpNtCb485mM6+lVxuUWlKBlrXeilt48cOVLOGntX3QmAShyFyi4QGqVowaPhaa4BQCm3NKlaI04FuXX09/fPjgvrUF1vANShLAYACKOCQIpZA5qrNqgYnOsL29GjkNSz2aD3BkChUNilzsifqQ6pdCBrsVBW4zn1HVZHXQeCgBAEa9v62RYtZllMhNgP06N3ar39dq2bny+ug07ua1rA+d8DA6bfhM8fj7hNLKpk8ztV7YtUV9cK6phcuXKlNkCsD3kD4MCBA+dVpN+kLdbGjRt7e3p6ys5YHVNHMo3yyZOx8s36QqfZLSht/YlHWUek8N9rRQ9gMGE6x+z7iCZ2fmseNuDHGwDVlk0zV30CQFl9GUGEgqnEn+FTWldRiVcjnyMAev8cDiorI0ca7+CGAYASyqTJA5hFit4FjiZEUtX0GaJp7XVsnt0GZ3aOlrGSzw9dQENx3TAAaFg5unnz5gcEggUCgYG/+gRPq9K3K6xqgdOC+A7vZLhYoloG5LhU/Y1P6588e8Wr+hJUzpEyHpC5/5fly81UOpq9qAZgW3+o8GHJ4xG44fN1OIfelXOsPkbDAKCiFYaGhv4vWsQtW7bQj/AihMn4+bQE7GMzmbdYpRdY9VC8rRBlPK8yngnLSF6ax437/At79+79tU3T6HMjATCnbkJ7J63AlxAwAvUh0tqW6JM+bZoUZSRK06ipAFCt+7LsE+BKONIS0MP8+7oA0sV68BWzBvAW9JzVOV5QMVEdIzQVABLA4+oH3KD6pdeaQxjio022OzeK52NpQIDyWWzxvNbYo0SfArBC6nC4N4CjWCXBKFxl26Wy/nsIfIpxqiRSg2/87W+DC5omu8HBwXsU7+U0AIAfSq91EgkQpLUCKF0TaP+hvtDnyT8P1FQLkLUA1LKMS0nL17qAtPEzipcrmeeqMLUKWC2sKzSttbJypse6pLUwMMHsc0ChBeg1Nzn5aSkAyLwekFwfoT9QJ2Jy/m91bEwDAhSveL9Ref5T5WGMz/3rdSqbF9uW6gN4SaDKRJrM+plegn0iDcjCFr9TPv/hKrNpWPSmjkEbVssMM1KrTtvns7nm2sq2AWDVdI2e2wC4RhVvq/3/x6JodFRVgLsAAAAASUVORK5CYII=",
    rdns: "com.dicewallet"
  };
  window.ethereum = provider;
  const announceDetail = Object.freeze({ info, provider });
  window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: announceDetail }));
  window.addEventListener("eip6963:requestProvider", () => {
    window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: announceDetail }));
  });
})();
