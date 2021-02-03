const display_width = 728;
const display_height = 255;
const wanted_num_points = 4000;

const path = document.querySelector("path");
const L = path.getTotalLength();

// Get `wanted_num_points` equally spaced points on the path.
const points = Array(wanted_num_points).fill().map((_, i) => {
  const P = path.getPointAtLength(i * L / wanted_num_points);
  return {x: P.x, y: P.y};
});

// Calculate bounding box of path
const minx = points.reduce((a, p) => Math.min(a, p.x-0.5), Infinity);
const maxx = points.reduce((a, p) => Math.max(a, p.x+0.5), -Infinity);
const miny = points.reduce((a, p) => Math.min(a, p.y-0.5), Infinity);
const maxy = points.reduce((a, p) => Math.max(a, p.y+0.5), -Infinity);

// Rescale points so the bounding box maps to the whole display size
const points_remapped = points.map(p => ({
  x: display_width - ~~((p.x-minx)/(maxx-minx)*display_width+0.5),
  y: ~~(display_height - (p.y-miny)/(maxy-miny)*display_height+0.5)
}));

// Create a C header file with the point list
const c_header = `
// Generated from ${window.location}

const struct point points[] = {${
  points_remapped.map(({x,y}) => `{${x},${y}}`).join(',')
}};
const long num_points = ${points_remapped.length};
`;

// And initiate a "download" of the generated file
const c_header_blob = new Blob([c_header], {type: "text/plain"});
window.location.assign(URL.createObjectURL(c_header_blob));
