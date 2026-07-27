# ChatGPT graphite portrait provenance

Generated 2026-07-27 with OpenAI's built-in image-generation tool, then
converted to 8-bit grayscale and stripped of metadata with ImageMagick. Each
asset is an original, provider-owned natural-history portrait on white paper.
Wisconsin DNR species descriptions and the edition's independently researched
identification claims supplied the morphology review criteria.

## Shared prompt contract

Every prompt requested one complete adult specimen in an exact left-facing
lateral profile; museum-quality fine graphite pencil; clean white background;
credible scales, fin rays, operculum, mouth, and diagnostic markings; and no
text, labels, border, ruler, hook, lure, scenery, shadow, or watermark.

Species-specific prompt clauses:

| Asset | Required visible distinctions |
|---|---|
| `black-crappie.png` | Deep slab body, oblique mouth, 7–8 dorsal spines, broad anal fin, irregular mottling |
| `bluegill.png` | Deep oval, tiny mouth, pointed pectoral, solid dark ear flap, faint bars |
| `cisco.png` | Slender salmonid, projecting lower jaw, adipose fin, large scales, deep fork |
| `largemouth-bass.png` | Jaw beyond eye, deep dorsal notch, horizontal side band |
| `muskellunge.png` | Long duckbill form, rear fins, pointed fork, dark-on-light bars |
| `northern-pike.png` | Long duckbill form, rounded caudal lobes, pale spots on dark ground |
| `pumpkinseed.png` | Compact deep body, short pectoral, pale-edged ear spot, cheek tracery |
| `rock-bass.png` | Elongate sunfish, large eye and mouth, spot rows, 5–7 anal spines |
| `smallmouth-bass.png` | Jaw to mid-eye, shallow dorsal notch, vertical side and cheek bars |
| `walleye.png` | Large reflective eye, two dorsals, dorsal saddles, white lower-tail tip |
| `yellow-perch.png` | Small mouth, two dorsals, seven vertical bars, hatched lower fins |

## Editorial processing

The generated masters were copied into
`src/lake-country-fishing/chatgpt/shared/portraits/`, converted to a true
grayscale color space, stripped of ancillary metadata, cropped to print-safe
white margins, and given a 98% white-point threshold to remove faint image
fields without erasing graphite detail. They are placed without stretching.
SHA-256 values below identify the published source assets.

```text
9bbc885258e7402c1e01bd3b7fe8ec86daad850ed95924e89ef461a10a5a7584  black-crappie.png
921d6c8797078c02fb146d3d4e98e7644264a43e102b29d7009d42117257f0c8  bluegill.png
5a1cab601190232927621ae97a8850f9844a87d71bc1ab657018c1a340ac980c  cisco.png
9d5edbf110cb1e5404da3f17b483543b1f94a6e6029ac8bbf170e01a3cc8e535  largemouth-bass.png
c129efbb529419d600cb0c2b6b1c8520bbec6b93f16a536639d246882da37e46  muskellunge.png
15bf436b0af78afb8df2a10af55921c43f82e7584f621363a1611349b10ace22  northern-pike.png
813f013c549cb0630fd8a5aa53ae9eb751e7212a1605c35e24ea2ad405581e85  pumpkinseed.png
4cff90da97dce95799a4c53e7b204a5244507e84b625bb0e9db01a376f357fa7  rock-bass.png
a091915dd9aaff45f1ecba623506eeafd7abce4263e52a3579ee2ccd19a79128  smallmouth-bass.png
844fb874c2f38336631e09cb975b61ac0ba74b8ff243cd72e6504ed633bbc3df  walleye.png
dc2204a7c473d523e23f23cbc77af2202c08b2691e55d384fad44dabe6170bb5  yellow-perch.png
```
