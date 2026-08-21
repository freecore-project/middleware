ZFS_ARC_MAX_MIN = 64 * 1024 * 1024


def effective_arc_min(arc_min=None, arc_c_min=None):
    return max(filter(None, (arc_min, arc_c_min)), default=0)


def minimum_valid_arc_max(arc_min=None, arc_c_min=None, all_memory=None):
    floor = effective_arc_min(arc_min, arc_c_min)
    minimum = max(ZFS_ARC_MAX_MIN, floor + 1)
    if all_memory is not None and minimum >= all_memory:
        return None
    return minimum


def arc_max_reject_reason(value, arc_min=None, arc_c_min=None, all_memory=None):
    if value is None:
        return 'arc_max is unavailable'

    if value == 0:
        return None

    if value < ZFS_ARC_MAX_MIN:
        return f'arc_max ({value}) is less than minimum allowed ARC max ({ZFS_ARC_MAX_MIN})'

    floor = effective_arc_min(arc_min, arc_c_min)
    if value <= floor:
        return f'arc_max ({value}) is not greater than effective ARC minimum ({floor})'

    if all_memory is not None and value >= all_memory:
        return f'arc_max ({value}) is not less than physical memory ({all_memory})'

    return None
