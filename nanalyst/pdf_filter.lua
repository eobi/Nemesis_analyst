-- Keeps wide content inside the page: tables get explicit column widths (so cells wrap), long inline code
-- can break anywhere, and fenced code blocks wrap.

local function esc(ch)
  if ch == "\\" then return "\\textbackslash{}" end
  if ch == "^" then return "\\textasciicircum{}" end
  if ch == "~" then return "\\textasciitilde{}" end
  if ch == " " then return "\\ " end
  if ch:match("[{}$&#_%%]") then return "\\" .. ch end
  return ch
end

function Code(el)
  local t = el.text
  if #t < 20 then return nil end
  local out = {}
  for ch in t:gmatch(utf8.charpattern) do
    out[#out + 1] = esc(ch) .. "\\allowbreak{}"
  end
  return pandoc.RawInline("latex", "{\\ttfamily\\footnotesize " .. table.concat(out) .. "}")
end

function CodeBlock(el)
  return pandoc.RawBlock("latex",
    "\\begin{Verbatim}[breaklines,breakanywhere,fontsize=\\footnotesize]\n" .. el.text .. "\n\\end{Verbatim}")
end

function Table(tbl)
  local n = #tbl.colspecs
  if n == 0 then return nil end
  local maxlen = {}
  for i = 1, n do maxlen[i] = 6 end
  local function scan(rows)
    for _, row in ipairs(rows) do
      for i, cell in ipairs(row.cells) do
        if i <= n then
          local l = #pandoc.utils.stringify(cell.contents)
          if l > maxlen[i] then maxlen[i] = l end
        end
      end
    end
  end
  scan(tbl.head.rows)
  for _, b in ipairs(tbl.bodies) do scan(b.body) end
  local w, tot = {}, 0
  for i = 1, n do
    w[i] = math.min(math.max(maxlen[i], 8), 44)
    tot = tot + w[i]
  end
  for i = 1, n do
    tbl.colspecs[i] = { tbl.colspecs[i][1], (w[i] / tot) * 0.97 }
  end
  return tbl
end

-- long bare tokens (hashes, file names in headings and prose) may break anywhere
function Str(el)
  local t = el.text
  if #t < 28 then return nil end
  local out = {}
  for ch in t:gmatch(utf8.charpattern) do
    out[#out + 1] = esc(ch) .. "\\allowbreak{}"
  end
  return pandoc.RawInline("latex", table.concat(out))
end

-- a lone \newpage line in the markdown is a page break, not text
function Para(el)
  if #el.content == 1 and el.content[1].t == "Str" and el.content[1].text == "\\newpage" then
    return pandoc.RawBlock("latex", "\\newpage")
  end
  return nil
end
