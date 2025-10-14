const deptEl = document.getElementById("department");
    const dayEl = document.getElementById("day");
    const timeEl = document.getElementById("time");
    const checkBtn = document.getElementById("checkBtn");
    const freeDiv = document.getElementById("freeResult");
    const occupiedDiv = document.getElementById("occupiedResult");

    let allData = [];
    let loaded = false;

    // 👇 add mapping for CSV files
    const files = [
      { name: "Physics", path: "static/physics.csv" },
      { name: "Chemistry", path: "static/chemistry.csv" },
      { name: "Data Science", path: "static/datascience.csv" }
    ];

    async function loadCSVs() {
      for (let f of files) {
        try {
          const res = await fetch(f.path);
          if (!res.ok) throw new Error(`Failed to load ${f.path}`);
          const text = await res.text();
          const lines = text.split('\n').slice(1); // skip header
          lines.forEach(line => {
            if (line.trim()) {
              const [dept, block, classroom, day, slot, subject, faculty] = line.split(',').map(s => s.trim());
              allData.push({ dept, block, classroom, day, slot, subject, faculty, fileDept: f.name });
            }
          });
        } catch (err) {
          console.error(err);
        }
      }

      // fill department dropdown based on file names
      files.forEach(f => {
        const option = document.createElement("option");
        option.value = f.name;
        option.textContent = f.name;
        deptEl.appendChild(option);
      });

      loaded = true;
    }

    function parseSlotTime(ts) {
      ts = ts.replace('.', ':').toLowerCase().trim();
      const isPM = ts.includes('pm');
      const isAM = ts.includes('am');
      ts = ts.replace(/am|pm/i, '').trim();
      let [h, m] = ts.split(':').map(Number);
      if (Number.isNaN(h) || Number.isNaN(m)) return null;
      if (isPM && h < 12) h += 12;
      if (isAM && h === 12) h = 0;
      return h * 60 + m;
    }

    function isTimeInSlot(userMin, slot) {
      let [startStr, endStr] = slot.split(' - ');
      if (!startStr || !endStr) return false;
      startStr = startStr.replace(/^S/i, '').trim();
      const start = parseSlotTime(startStr);
      const end = parseSlotTime(endStr);
      if (start === null || end === null) return false;
      return userMin >= start && userMin < end;
    }

    function parseUserTime(timeStr) {
      timeStr = timeStr.replace('.', ':').trim();
      const [uh, um] = timeStr.split(':').map(Number);
      if (Number.isNaN(uh) || Number.isNaN(um)) throw new Error('Invalid time format');
      const userMin = uh * 60 + um;
      if (userMin < 8*60+50 || userMin > 16*60+35) throw new Error('Enter timing between 8:50 - 16:35 only');
      return userMin;
    }

    checkBtn.addEventListener("click", async () => {
      const dept = deptEl.value;
      const day = dayEl.value;
      const time = timeEl.value.trim();
      if (!dept) { alert("Select department"); return; }
      if (!time) { alert("Enter a time (e.g., 8:50, 16:35)"); return; }

      freeDiv.style.display = "none";
      occupiedDiv.style.display = "none";
      checkBtn.textContent = "Checking...";

      try {
        if (!loaded) await loadCSVs();
        const userMin = parseUserTime(time);

        // filter records for this dept + day
        const deptData = allData.filter(entry => entry.fileDept === dept && entry.day === day);

        // Handle break time
        const breakStart = 10*60 + 30;
        const breakEnd = 10*60 + 45;
        if (userMin >= breakStart && userMin < breakEnd) {
          freeDiv.innerHTML = "⏰ Break Period";
          freeDiv.style.display = "block";
          occupiedDiv.innerHTML = "No occupied slots.";
          occupiedDiv.style.display = "block";
          checkBtn.textContent = "Check Slots";
          return;
        }

        // Free classrooms
        const freeClassrooms = deptData
          .filter(entry => isTimeInSlot(userMin, entry.slot) && (!entry.subject || entry.subject.trim() === ""))
          .map(entry => `${entry.block} - ${entry.classroom}`);

        // Occupied classrooms
        const occupiedDetails = deptData
          .filter(entry => isTimeInSlot(userMin, entry.slot) && entry.subject && entry.subject.trim() !== "" && entry.subject.toLowerCase() !== "break")
          .map(entry => ({
            block: entry.block,
            classroom: entry.classroom,
            subject: entry.subject,
            faculty: entry.faculty
          }));

        freeDiv.innerHTML = freeClassrooms.length > 0 ?
          `<strong>Free Slots:</strong><br/>${[...new Set(freeClassrooms)].join("<br/>")}` :
          "No free slots available.";
        freeDiv.style.display = "block";

        if (occupiedDetails.length > 0) {
          const occupiedHtml = occupiedDetails.map(d =>
            `<div class="occupied-box">
              <strong>Block:</strong> ${d.block}<br/>
              <strong>Classroom:</strong> ${d.classroom}<br/>
              <strong>Course:</strong> ${d.subject}<br/>
              <strong>Faculty:</strong> ${d.faculty}
            </div>`
          ).join("");
          occupiedDiv.innerHTML = occupiedHtml;
        } else {
          occupiedDiv.innerHTML = "No occupied slots.";
        }
        occupiedDiv.style.display = "flex";

      } catch (err) {
        alert(err.message || "Error processing data.");
        console.error(err);
      } finally {
        checkBtn.textContent = "Check Slots";
      }
    });

    loadCSVs();