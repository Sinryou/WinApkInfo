# -*- coding: utf-8 -*-
"""Android 颜色解析与框架预设颜色表。"""
import re


def parse_android_color(color_str: str):
    """
    把 Android 颜色字符串转成 Pillow 可用的 (R, G, B, A)。

    支持 Android 认可的四种写法：#RGB、#ARGB、#RRGGBB、#AARRGGBB。
    旧实现只认 6/8 位，`#f00` 这类合法简写会抛异常导致整层填充被静默跳过；
    非法输入（如 `#gggggg`）抛的也是底层的 ValueError，不是统一的格式错误。
    """
    s = (color_str or "").strip().lstrip('#')
    try:
        if len(s) == 3:      # RGB
            r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, 255)
        if len(s) == 4:      # ARGB
            a, r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, a)
        if len(s) == 6:      # RRGGBB
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), 255)
        if len(s) == 8:      # AARRGGBB
            return (int(s[2:4], 16), int(s[4:6], 16), int(s[6:8], 16), int(s[0:2], 16))
    except ValueError:
        pass
    raise ValueError("不合法的颜色格式: " + str(color_str))


# Android 框架（android 包）颜色资源表：键为 AOSP public-final.xml 中的公开
# color 资源 ID，值为 colors*.xml 的默认 ARGB。用于解析 0x01xxxxxx 引用
# （自适应图标背景/前景常直接引用 @android:color/...）。
#
# system_* 是 Material You 动态色，设备上可被 OverlayManager 按壁纸替换；
# 这里使用 AOSP 默认调色板（Pixel 默认主题）。静态解析拿不到用户主题，
# 取默认值仍能渲染出接近真实图标的颜色，比按"未知"当透明更可用。
_FRAMEWORK_COLOR_MAP = {
    "0x01060000": "#ffaaaaaa",  # darker_gray
    "0x0106000b": "#ffffffff",  # white
    "0x0106000c": "#ff000000",  # black
    "0x0106000d": "#00000000",  # transparent
    "0x0106000e": "#ff000000",  # background_dark
    "0x0106000f": "#ffffffff",  # background_light
    "0x01060012": "#ff33b5e5",  # holo_blue_light
    "0x01060013": "#ff0099cc",  # holo_blue_dark
    "0x01060014": "#ff99cc00",  # holo_green_light
    "0x01060015": "#ff669900",  # holo_green_dark
    "0x01060016": "#ffff4444",  # holo_red_light
    "0x01060017": "#ffcc0000",  # holo_red_dark
    "0x01060018": "#ffffbb33",  # holo_orange_light
    "0x01060019": "#ffff8800",  # holo_orange_dark
    "0x0106001a": "#ffaa66cc",  # holo_purple
    "0x0106001b": "#ff00ddff",  # holo_blue_bright
    "0x0106001c": "#00000000",  # system_notification_accent_color
    "0x0106001d": "#ffffffff",  # system_neutral1_0
    "0x0106001e": "#fffefbff",  # system_neutral1_10
    "0x0106001f": "#fff1f0f7",  # system_neutral1_50
    "0x01060020": "#ffe2e2e9",  # system_neutral1_100
    "0x01060021": "#ffc6c6cd",  # system_neutral1_200
    "0x01060022": "#ffababb1",  # system_neutral1_300
    "0x01060023": "#ff909097",  # system_neutral1_400
    "0x01060024": "#ff76777d",  # system_neutral1_500
    "0x01060025": "#ff5d5e64",  # system_neutral1_600
    "0x01060026": "#ff45464c",  # system_neutral1_700
    "0x01060027": "#ff2f3036",  # system_neutral1_800
    "0x01060028": "#ff1a1b20",  # system_neutral1_900
    "0x01060029": "#ff000000",  # system_neutral1_1000
    "0x0106002a": "#ffffffff",  # system_neutral2_0
    "0x0106002b": "#fffefbff",  # system_neutral2_10
    "0x0106002c": "#fff0f0fa",  # system_neutral2_50
    "0x0106002d": "#ffe1e2ec",  # system_neutral2_100
    "0x0106002e": "#ffc5c6d0",  # system_neutral2_200
    "0x0106002f": "#ffa9abb4",  # system_neutral2_300
    "0x01060030": "#ff8f9099",  # system_neutral2_400
    "0x01060031": "#ff757780",  # system_neutral2_500
    "0x01060032": "#ff5c5e67",  # system_neutral2_600
    "0x01060033": "#ff44464f",  # system_neutral2_700
    "0x01060034": "#ff2e3038",  # system_neutral2_800
    "0x01060035": "#ff191b23",  # system_neutral2_900
    "0x01060036": "#ff000000",  # system_neutral2_1000
    "0x01060037": "#ffffffff",  # system_accent1_0
    "0x01060038": "#fffefbff",  # system_accent1_10
    "0x01060039": "#ffeef0ff",  # system_accent1_50
    "0x0106003a": "#ffd9e2ff",  # system_accent1_100
    "0x0106003b": "#ffb0c6ff",  # system_accent1_200
    "0x0106003c": "#ff94aae4",  # system_accent1_300
    "0x0106003d": "#ff7a90c8",  # system_accent1_400
    "0x0106003e": "#ff6076ac",  # system_accent1_500
    "0x0106003f": "#ff475d92",  # system_accent1_600
    "0x01060040": "#ff2f4578",  # system_accent1_700
    "0x01060041": "#ff152e60",  # system_accent1_800
    "0x01060042": "#ff001945",  # system_accent1_900
    "0x01060043": "#ff000000",  # system_accent1_1000
    "0x01060044": "#ffffffff",  # system_accent2_0
    "0x01060045": "#fffefbff",  # system_accent2_10
    "0x01060046": "#ffeef0ff",  # system_accent2_50
    "0x01060047": "#ffdce2f9",  # system_accent2_100
    "0x01060048": "#ffc0c6dc",  # system_accent2_200
    "0x01060049": "#ffa4abc1",  # system_accent2_300
    "0x0106004a": "#ff8a90a5",  # system_accent2_400
    "0x0106004b": "#ff70778b",  # system_accent2_500
    "0x0106004c": "#ff575e71",  # system_accent2_600
    "0x0106004d": "#ff404659",  # system_accent2_700
    "0x0106004e": "#ff2a3042",  # system_accent2_800
    "0x0106004f": "#ff151b2c",  # system_accent2_900
    "0x01060050": "#ff000000",  # system_accent2_1000
    "0x01060051": "#ffffffff",  # system_accent3_0
    "0x01060052": "#fffffbff",  # system_accent3_10
    "0x01060053": "#ffffebfa",  # system_accent3_50
    "0x01060054": "#fffdd7fa",  # system_accent3_100
    "0x01060055": "#ffe0bbdd",  # system_accent3_200
    "0x01060056": "#ffc3a0c1",  # system_accent3_300
    "0x01060057": "#ffa886a6",  # system_accent3_400
    "0x01060058": "#ff8c6d8c",  # system_accent3_500
    "0x01060059": "#ff725572",  # system_accent3_600
    "0x0106005a": "#ff593d59",  # system_accent3_700
    "0x0106005b": "#ff412742",  # system_accent3_800
    "0x0106005c": "#ff2a122c",  # system_accent3_900
    "0x0106005d": "#ff000000",  # system_accent3_1000
    "0x0106005e": "#ffd9e2ff",  # system_primary_container_light
    "0x0106005f": "#ff2f4578",  # system_on_primary_container_light
    "0x01060060": "#ff475d92",  # system_primary_light
    "0x01060061": "#ffffffff",  # system_on_primary_light
    "0x01060062": "#ffdce2f9",  # system_secondary_container_light
    "0x01060063": "#ff404659",  # system_on_secondary_container_light
    "0x01060064": "#ff575e71",  # system_secondary_light
    "0x01060065": "#ffffffff",  # system_on_secondary_light
    "0x01060066": "#fffdd7fa",  # system_tertiary_container_light
    "0x01060067": "#ff593d59",  # system_on_tertiary_container_light
    "0x01060068": "#ff725572",  # system_tertiary_light
    "0x01060069": "#ffffffff",  # system_on_tertiary_light
    "0x0106006a": "#fffaf8ff",  # system_background_light
    "0x0106006b": "#ff1a1b20",  # system_on_background_light
    "0x0106006c": "#fffaf8ff",  # system_surface_light
    "0x0106006d": "#ff1a1b20",  # system_on_surface_light
    "0x0106006e": "#fff4f3fa",  # system_surface_container_low_light
    "0x0106006f": "#ffffffff",  # system_surface_container_lowest_light
    "0x01060070": "#ffeeedf4",  # system_surface_container_light
    "0x01060071": "#ffe8e7ef",  # system_surface_container_high_light
    "0x01060072": "#ffe2e2e9",  # system_surface_container_highest_light
    "0x01060073": "#fffaf8ff",  # system_surface_bright_light
    "0x01060074": "#ffdad9e0",  # system_surface_dim_light
    "0x01060075": "#ffe1e2ec",  # system_surface_variant_light
    "0x01060076": "#ff44464f",  # system_on_surface_variant_light
    "0x01060077": "#ff757780",  # system_outline_light
    "0x01060078": "#ffba1a1a",  # system_error_light
    "0x01060079": "#ffffffff",  # system_on_error_light
    "0x0106007a": "#ffffdad6",  # system_error_container_light
    "0x0106007b": "#ff93000a",  # system_on_error_container_light
    "0x0106007c": "#ffd9e2ff",  # system_control_activated_light
    "0x0106007d": "#ff44464f",  # system_control_normal_light
    "0x0106007e": "#ff000000",  # system_control_highlight_light
    "0x0106007f": "#ffe2e2e9",  # system_text_primary_inverse_light
    "0x01060080": "#ffc5c6d0",  # system_text_secondary_and_tertiary_inverse_light
    "0x01060081": "#ffe2e2e9",  # system_text_primary_inverse_disable_only_light
    "0x01060082": "#ffe2e2e9",  # system_text_secondary_and_tertiary_inverse_disabled_light
    "0x01060083": "#ffe2e2e9",  # system_text_hint_inverse_light
    "0x01060084": "#ff6076ac",  # system_palette_key_color_primary_light
    "0x01060085": "#ff70778b",  # system_palette_key_color_secondary_light
    "0x01060086": "#ff8c6d8c",  # system_palette_key_color_tertiary_light
    "0x01060087": "#ff76777d",  # system_palette_key_color_neutral_light
    "0x01060088": "#ff757780",  # system_palette_key_color_neutral_variant_light
    "0x01060089": "#ff2f4578",  # system_primary_container_dark
    "0x0106008a": "#ffd9e2ff",  # system_on_primary_container_dark
    "0x0106008b": "#ffb0c6ff",  # system_primary_dark
    "0x0106008c": "#ff152e60",  # system_on_primary_dark
    "0x0106008d": "#ff404659",  # system_secondary_container_dark
    "0x0106008e": "#ffdce2f9",  # system_on_secondary_container_dark
    "0x0106008f": "#ffc0c6dc",  # system_secondary_dark
    "0x01060090": "#ff2a3042",  # system_on_secondary_dark
    "0x01060091": "#ff593d59",  # system_tertiary_container_dark
    "0x01060092": "#fffdd7fa",  # system_on_tertiary_container_dark
    "0x01060093": "#ffe0bbdd",  # system_tertiary_dark
    "0x01060094": "#ff412742",  # system_on_tertiary_dark
    "0x01060095": "#ff121318",  # system_background_dark
    "0x01060096": "#ffe2e2e9",  # system_on_background_dark
    "0x01060097": "#ff121318",  # system_surface_dark
    "0x01060098": "#ffe2e2e9",  # system_on_surface_dark
    "0x01060099": "#ff1a1b20",  # system_surface_container_low_dark
    "0x0106009a": "#ff0c0e13",  # system_surface_container_lowest_dark
    "0x0106009b": "#ff1e1f25",  # system_surface_container_dark
    "0x0106009c": "#ff282a2f",  # system_surface_container_high_dark
    "0x0106009d": "#ff33343a",  # system_surface_container_highest_dark
    "0x0106009e": "#ff38393f",  # system_surface_bright_dark
    "0x0106009f": "#ff121318",  # system_surface_dim_dark
    "0x010600a0": "#ff44464f",  # system_surface_variant_dark
    "0x010600a1": "#ffc5c6d0",  # system_on_surface_variant_dark
    "0x010600a2": "#ff8f9099",  # system_outline_dark
    "0x010600a3": "#ffffb4ab",  # system_error_dark
    "0x010600a4": "#ff690005",  # system_on_error_dark
    "0x010600a5": "#ff93000a",  # system_error_container_dark
    "0x010600a6": "#ffffdad6",  # system_on_error_container_dark
    "0x010600a7": "#ff2f4578",  # system_control_activated_dark
    "0x010600a8": "#ffc5c6d0",  # system_control_normal_dark
    "0x010600a9": "#ffffffff",  # system_control_highlight_dark
    "0x010600aa": "#ff1a1b20",  # system_text_primary_inverse_dark
    "0x010600ab": "#ff44464f",  # system_text_secondary_and_tertiary_inverse_dark
    "0x010600ac": "#ff1a1b20",  # system_text_primary_inverse_disable_only_dark
    "0x010600ad": "#ff1a1b20",  # system_text_secondary_and_tertiary_inverse_disabled_dark
    "0x010600ae": "#ff1a1b20",  # system_text_hint_inverse_dark
    "0x010600af": "#ff6076ac",  # system_palette_key_color_primary_dark
    "0x010600b0": "#ff70778b",  # system_palette_key_color_secondary_dark
    "0x010600b1": "#ff8c6d8c",  # system_palette_key_color_tertiary_dark
    "0x010600b2": "#ff76777d",  # system_palette_key_color_neutral_dark
    "0x010600b3": "#ff757780",  # system_palette_key_color_neutral_variant_dark
    "0x010600b4": "#ffd9e2ff",  # system_primary_fixed
    "0x010600b5": "#ffb0c6ff",  # system_primary_fixed_dim
    "0x010600b6": "#ff001945",  # system_on_primary_fixed
    "0x010600b7": "#ff2f4578",  # system_on_primary_fixed_variant
    "0x010600b8": "#ffdce2f9",  # system_secondary_fixed
    "0x010600b9": "#ffc0c6dc",  # system_secondary_fixed_dim
    "0x010600ba": "#ff151b2c",  # system_on_secondary_fixed
    "0x010600bb": "#ff404659",  # system_on_secondary_fixed_variant
    "0x010600bc": "#fffdd7fa",  # system_tertiary_fixed
    "0x010600bd": "#ffe0bbdd",  # system_tertiary_fixed_dim
    "0x010600be": "#ff2a122c",  # system_on_tertiary_fixed
    "0x010600bf": "#ff593d59",  # system_on_tertiary_fixed_variant
    "0x010600c0": "#ffc5c6d0",  # system_outline_variant_light
    "0x010600c1": "#ff44464f",  # system_outline_variant_dark
    "0x010600c5": "#ffffffff",  # system_error_0
    "0x010600c6": "#fffffbff",  # system_error_10
    "0x010600c7": "#ffffedea",  # system_error_50
    "0x010600c8": "#ffffdad6",  # system_error_100
    "0x010600c9": "#ffffb4ab",  # system_error_200
    "0x010600ca": "#ffff897d",  # system_error_300
    "0x010600cb": "#ffff5449",  # system_error_400
    "0x010600cc": "#ffde3730",  # system_error_500
    "0x010600cd": "#ffba1a1a",  # system_error_600
    "0x010600ce": "#ff93000a",  # system_error_700
    "0x010600cf": "#ff690005",  # system_error_800
    "0x010600d0": "#ff410002",  # system_error_900
    "0x010600d1": "#ff000000",  # system_error_1000
}
