import { createHash } from "crypto";

// A recipe is now a complete ad archetype, rather than a bag of unrelated
// adjectives. The model may vary the execution, but every slot starts with a
// recognisable human or strategic job. This preserves surprise without asking
// Pexels footage to rescue an incoherent concept later.
const CREATIVE_ARCHETYPES = [
  {
    id: "listener_recognition",
    risk: "accessible",
    mechanism: "listener self-recognition",
    hook_focus: "audience story",
    story_job: "make the intended listener feel accurately seen",
    visual_worlds: ["soft cinematic realism", "lo-fi intimate realism", "rainy urban atmosphere"],
    footage_strategies: ["one emotionally legible human moment", "a solitary person moving through a real place", "a close human reaction with useful negative space"],
    copy_voices: ["emotionally honest", "warmly observant", "poetic but plain"],
    hook_structures: ["plain observation", "specific mood statement", "POV"],
    typography: ["bold_center", "minimal_bottom"],
  },
  {
    id: "listening_moment",
    risk: "accessible",
    mechanism: "recognisable listening situation",
    hook_focus: "listening moment",
    story_job: "name a real moment in which this playlist becomes useful",
    visual_worlds: ["nighttime cinematic realism", "bright everyday daylight", "handheld social realism"],
    footage_strategies: ["a person in a specific everyday transition", "a moving commute, walk, work or late-night scene", "a small human action with an obvious emotional state"],
    copy_voices: ["confidently direct", "internet-native but natural", "warmly observant"],
    hook_structures: ["specific mood statement", "simple invitation", "POV"],
    typography: ["editorial_top", "minimal_bottom"],
  },
  {
    id: "discovery_promise",
    risk: "accessible",
    mechanism: "clear discovery promise",
    hook_focus: "playlist benefit",
    story_job: "promise fresher or less predictable music without sounding like generic ad copy",
    visual_worlds: ["editorial realism", "cinematic motion", "nighttime neon"],
    footage_strategies: ["forward movement through a visually rich place", "a curious person actively discovering something", "an expressive environment with visible motion and text space"],
    copy_voices: ["confidently direct", "playfully specific", "plainspoken"],
    hook_structures: ["direct benefit", "compact contrast", "imperative"],
    typography: ["bold_center", "editorial_top"],
  },
  {
    id: "emotional_shift",
    risk: "accessible",
    mechanism: "small emotional transformation",
    hook_focus: "emotional truth",
    story_job: "show the emotional change the music can create, not the object visible in the clip",
    visual_worlds: ["soft cinematic realism", "dreamy natural light", "moody urban realism"],
    footage_strategies: ["a human scene with a readable before-or-after feeling", "a calm-to-energised movement", "weather, light or motion supporting a human emotion"],
    copy_voices: ["poetic but plain", "emotionally honest", "romantic but concrete"],
    hook_structures: ["compact contrast", "plain observation", "mini plot twist"],
    typography: ["bold_center", "minimal_bottom"],
  },
  {
    id: "taste_identity",
    risk: "accessible",
    mechanism: "music taste identity signal",
    hook_focus: "identity",
    story_job: "give the listener a tasteful line they might share or recognise themselves in",
    visual_worlds: ["editorial portrait", "youth-culture realism", "quiet cinematic confidence"],
    footage_strategies: ["a distinctive person with attitude but no staged headphone cliché", "a social or fashion moment with natural motion", "a confident portrait in a real environment"],
    copy_voices: ["confidently direct", "understated", "internet-native but natural"],
    hook_structures: ["plain observation", "quoted dialogue", "compact contrast"],
    typography: ["editorial_top", "bold_center"],
  },
  {
    id: "open_invitation",
    risk: "accessible",
    mechanism: "simple emotional invitation",
    hook_focus: "invitation",
    story_job: "invite a click with warmth or curiosity instead of manufactured urgency",
    visual_worlds: ["warm candid realism", "sunlit movement", "night walk atmosphere"],
    footage_strategies: ["an inviting human movement toward or through a place", "a candid shared moment", "a visually pleasant journey with a clear focal subject"],
    copy_voices: ["warmly observant", "plainspoken", "quietly confident"],
    hook_structures: ["simple invitation", "question", "imperative"],
    typography: ["minimal_bottom", "editorial_top"],
  },
  {
    id: "strange_world",
    risk: "creative",
    mechanism: "campaign-world metaphor",
    hook_focus: "creative contrast",
    story_job: "extend the authored campaign world with one understandable imaginative leap",
    visual_worlds: ["retro-futurist atmosphere", "dreamlike landscape", "abstract light and reflections", "ordinary life made slightly strange"],
    footage_strategies: ["a cinematic environment that feels like another world", "abstract motion with a strong focal point", "an uncanny but beautiful real-world scene"],
    copy_voices: ["poetic but plain", "slightly uncanny", "dry deadpan"],
    hook_structures: ["one-line mystery", "compact contrast", "mini plot twist"],
    typography: ["editorial_top", "bold_center"],
  },
  {
    id: "visual_poetry",
    risk: "creative",
    mechanism: "sensory visual association",
    hook_focus: "emotional truth",
    story_job: "pair the playlist story with a memorable sensory image while keeping the hook independent of the footage noun",
    visual_worlds: ["macro texture in motion", "rain, light or reflections", "color and shadow as atmosphere"],
    footage_strategies: ["visually rich motion with generous text space", "one hypnotic natural or abstract process", "light, weather or texture carrying an emotion"],
    copy_voices: ["poetic but plain", "mysterious", "warmly observant"],
    hook_structures: ["specific mood statement", "one-line mystery", "plain observation"],
    typography: ["minimal_bottom", "editorial_top"],
  },
  {
    id: "earned_wildcard",
    risk: "wildcard",
    mechanism: "one earned pattern interruption",
    hook_focus: "wildcard",
    story_job: "surprise immediately, then make the connection to the playlist understandable in one beat",
    visual_worlds: ["awkward everyday comedy", "surreal object cinema", "colorful visual overload", "false documentary"],
    footage_strategies: ["one unmistakable strange subject in motion", "a genuinely funny found moment", "a visually magnetic object or process with a clean composition"],
    copy_voices: ["dry deadpan", "understated absurdity", "self-aware anti-ad"],
    hook_structures: ["deadpan documentary caption", "object label", "mini plot twist"],
    typography: ["bold_center", "editorial_top"],
  },
];

const SERENDIPITY_WORDS = [
  "jellyfish", "laundromat", "magnets", "pigeon", "chrome", "motel", "toaster",
  "aquarium", "escalator", "balloon", "supermarket", "fog", "plastic", "satellite",
  "mushroom", "carwash", "mirror", "cake", "elevator", "antenna", "receipt",
  "bubbles", "fluorescent", "parking", "vacuum", "arcade", "snow", "ceramic",
  "conveyor", "insects", "clouds", "scanner", "fruit", "mannequin", "sprinkler",
  "tunnel", "glitter", "microscope", "traffic", "curtain", "fish", "machine",
];

const SERENDIPITY_MODIFIERS = [
  "strange", "dreamy", "awkward", "hypnotic", "surreal", "lonely", "funny",
  "glowing", "slow motion", "close up", "at night", "retro", "abstract",
  "unexpected", "colorful", "cinematic", "handheld", "macro",
];

const BATCH_TONE_PROFILES = [
  ["accessible", "accessible", "accessible", "accessible", "accessible", "creative", "creative", "wildcard"],
  ["accessible", "accessible", "accessible", "accessible", "accessible", "accessible", "creative", "wildcard"],
  ["accessible", "accessible", "accessible", "accessible", "creative", "creative", "creative", "wildcard"],
];

function seededRandom(seed) {
  let state = Number.parseInt(createHash("sha256").update(String(seed)).digest("hex").slice(0, 8), 16) || 1;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function draw(pool, random, recent = []) {
  const fresh = pool.filter((item) => !recent.includes(item));
  const choices = fresh.length ? fresh : pool;
  return choices[Math.floor(random() * choices.length)];
}

function shuffle(values, random) {
  const copy = [...values];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const target = Math.floor(random() * (index + 1));
    [copy[index], copy[target]] = [copy[target], copy[index]];
  }
  return copy;
}

export function buildCreativeDeck(seed, count = 8) {
  const random = seededRandom(seed);
  const toneProfile = draw(BATCH_TONE_PROFILES, random);
  const requestedTones = Array.from({ length: count }, (_, index) => toneProfile[index % toneProfile.length]);
  const wildcardCount = Math.max(1, requestedTones.filter((tone) => tone === "wildcard").length);
  const nonWildcardTones = shuffle(requestedTones.filter((tone) => tone !== "wildcard"), random);
  const toneMix = [...nonWildcardTones.slice(0, Math.max(0, count - wildcardCount)), ...Array(wildcardCount).fill("wildcard")].slice(0, count);
  const usedHookStructures = new Set();
  const usedArchetypes = new Set();
  const creativeSlots = toneMix.map((tone, index) => tone === "creative" ? index + 1 : null).filter(Boolean);
  const lateralSearchCount = Math.min(creativeSlots.length, Math.floor(random() * 2));
  const lateralSearchSlots = new Set([
    ...shuffle(creativeSlots, random).slice(0, lateralSearchCount),
    ...toneMix.map((tone, index) => tone === "wildcard" ? index + 1 : null).filter(Boolean),
  ]);
  const recipes = [];
  for (let index = 0; index < count; index += 1) {
    const recent = recipes.slice(-3);
    const firstSerendipityWord = draw(SERENDIPITY_WORDS, random);
    const risk = toneMix[index];
    const archetypePool = CREATIVE_ARCHETYPES.filter((item) => item.risk === risk);
    const freshArchetypes = archetypePool.filter((item) => !usedArchetypes.has(item.id));
    const archetype = draw(freshArchetypes.length ? freshArchetypes : archetypePool, random);
    usedArchetypes.add(archetype.id);
    const structurePool = archetype.hook_structures;
    const availableStructures = structurePool.filter((item) => !usedHookStructures.has(item));
    const hookStructure = draw(availableStructures.length ? availableStructures : structurePool, random);
    usedHookStructures.add(hookStructure);
    const lateralSearch = lateralSearchSlots.has(index + 1);
    recipes.push({
      slot: index + 1,
      mode: risk === "accessible" ? "reliable" : risk,
      archetype: archetype.id,
      mechanism: archetype.mechanism,
      story_job: archetype.story_job,
      visual_world: draw(archetype.visual_worlds, random, recent.map((item) => item.visual_world)),
      copy_voice: draw(archetype.copy_voices, random, recent.map((item) => item.copy_voice)),
      hook_structure: hookStructure,
      hook_focus: archetype.hook_focus,
      footage_strategy: draw(archetype.footage_strategies, random, recent.map((item) => item.footage_strategy)),
      typography: draw(archetype.typography, random, recent.map((item) => item.typography)),
      risk_level: risk,
      workflow: risk === "wildcard" && random() < 0.45 ? "footage_first" : "concept_first",
      visual_role: lateralSearch ? "lateral_support" : "direct_support",
      lateral_search: lateralSearch,
      serendipity_words: lateralSearch ? [
        firstSerendipityWord,
        draw(SERENDIPITY_WORDS, random, [firstSerendipityWord]),
      ] : [],
      serendipity_modifier: lateralSearch ? draw(SERENDIPITY_MODIFIERS, random) : "",
      quality_bar: risk === "accessible"
        ? "emotionally legible in one second; the clip supports a person, mood or listening situation and never supplies the hook's idea"
        : risk === "creative"
          ? "one imaginative leap with an immediate emotional connection"
          : "a genuine pattern interrupt with a clear playlist payoff",
    });
  }
  return { seed: String(seed), recipes };
}

export function serendipityPexelsQuery(recipe = {}, seed = "") {
  const random = seededRandom(`${seed}:${recipe.slot || 0}:${recipe.serendipity_words?.join(":") || ""}`);
  const words = Array.isArray(recipe.serendipity_words) && recipe.serendipity_words.length
    ? recipe.serendipity_words
    : [draw(SERENDIPITY_WORDS, random), draw(SERENDIPITY_WORDS, random)];
  const word = words[Math.floor(random() * words.length)];
  const modifier = recipe.serendipity_modifier || draw(SERENDIPITY_MODIFIERS, random);
  return `${modifier} ${word}`.replace(/\s+/g, " ").trim().slice(0, 120);
}
