<?php

namespace Apex\Autentica\Core\Services;

use Apex\Autentica\Core\Exceptions\LastAdministratorException;
use Apex\Autentica\Core\Exceptions\ProtectedGroupException;
use Apex\Autentica\Core\Models\Group;
use Apex\Autentica\Core\Models\Permission;
use Apex\Autentica\Core\Models\SystemResource;
use Apex\Autentica\Core\Support\PermissionMap;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Everything that changes a group, in one place — P/004.
 *
 * This lived in a host controller, which meant anyone building their own interface on
 * Autentica had to rewrite it. That is not a reasonable thing to ask, because three of the
 * behaviours here exist only to stop an installation locking itself out and none of them
 * are obvious:
 *
 *   - permission rows are FORCE-deleted, never soft-deleted. `au10_permissions` has a
 *     unique index on (holder, resource) and a unique index does not know about
 *     `deleted_at`, so a trashed row would block that pair ever being granted again.
 *   - the protected group cannot be renamed, deleted, or have its matrix rewritten. The
 *     host matches that group BY NAME, so a rename turns every administrator check false.
 *   - the last member of a protected group cannot be removed.
 *
 * And two cache rules that look inconsistent and are not: a permission or group change
 * clears EVERYONE's cache, because the permission map every signed-in user resolves
 * against has changed; a membership change clears only that user's, because rebuilding
 * everybody's for a change that affected one person is waste.
 *
 * The UI package is a skin over this. A host that writes its own screens calls the same
 * methods and inherits every guard.
 */
class GroupAdministration
{
    public function __construct(private PermissionCache $cache)
    {
    }

    /**
     * Groups the installation may not rename, delete or re-permission.
     *
     * Configuration rather than a constant, because the name is the host's: TBX calls it
     * "Administrators" and another installation need not.
     *
     * @return array<int, string>
     */
    public function protectedGroups(): array
    {
        return (array) config('autentica.permissions.protected_groups', ['Administrators']);
    }

    public function isProtected(Group $group): bool
    {
        return in_array($group->name, $this->protectedGroups(), true);
    }

    /**
     * @throws ProtectedGroupException
     */
    public function assertNotProtected(Group $group, string $verb): void
    {
        if ($this->isProtected($group)) {
            throw new ProtectedGroupException(
                "The {$group->name} group cannot be {$verb}."
            );
        }
    }

    /**
     * Create a group, optionally starting from another group's permissions.
     *
     * A copy taken now, not a link — later changes to the source do not follow.
     */
    public function create(string $name, ?string $description = null, ?int $copyFromGroupId = null): Group
    {
        return DB::transaction(function () use ($name, $description, $copyFromGroupId) {
            $group = Group::create([
                'name' => $name,
                'description' => $description,
            ]);

            if ($copyFromGroupId) {
                $group->copyPermissionsFrom(Group::findOrFail($copyFromGroupId));
            }

            // A new group can hold permissions from the moment it exists, so the map every
            // signed-in user resolves against has changed.
            $this->cache->clearAllCache();

            return $group;
        });
    }

    /**
     * @throws ProtectedGroupException
     */
    public function rename(Group $group, string $name, ?string $description = null): Group
    {
        $this->assertNotProtected($group, 'renamed');

        $group->update(['name' => $name, 'description' => $description]);

        return $group;
    }

    /**
     * Delete a group, and say how many people were in it.
     *
     * Members are detached as part of the delete rather than being a precondition for it —
     * the caller is expected to have said how many will lose the group, so the consequence
     * is in front of whoever is deciding.
     *
     * @return int members who were removed
     * @throws ProtectedGroupException
     */
    public function delete(Group $group): int
    {
        $this->assertNotProtected($group, 'deleted');

        $members = $group->users()->count();

        DB::transaction(function () use ($group) {
            $group->users()->detach();

            // forceDelete, for the reason in the class docblock: trashed rows would block a
            // future group reusing this id, and they are unreachable in any case.
            Permission::withTrashed()
                ->where('permissionable_type', $group->getMorphClass())
                ->where('permissionable_id', $group->id)
                ->forceDelete();

            $group->delete();
        });

        // Everyone's, not just the members': the group is gone from the permission map.
        $this->cache->clearAllCache();

        return $members;
    }

    /**
     * Replace one group's permissions with the letters supplied.
     *
     * Keyed by resource identifier: `['events' => 'cru', 'venues' => '']`. An empty string
     * means no access, and removes the row rather than storing an all-false one, so the
     * matrix and the database agree. Identifiers the system does not know are skipped —
     * validating them is the caller's job and this must not invent rows either way.
     *
     * @param array<string, string> $permissions
     * @throws ProtectedGroupException
     */
    public function setMatrix(Group $group, array $permissions): void
    {
        $this->assertNotProtected($group, 'edited here');

        DB::transaction(function () use ($group, $permissions) {
            $resources = SystemResource::whereIn('identifier', array_keys($permissions))
                ->get()
                ->keyBy('identifier');

            foreach ($permissions as $identifier => $letters) {
                $resource = $resources->get($identifier);

                if (! $resource) {
                    continue;
                }

                $letters = (string) $letters;

                if ($letters === '') {
                    Permission::withTrashed()
                        ->where('permissionable_type', $group->getMorphClass())
                        ->where('permissionable_id', $group->id)
                        ->where('system_resource_id', $resource->id)
                        ->forceDelete();

                    continue;
                }

                Permission::createFor($group, $resource, $this->actionsFromLetters($letters));
            }
        });

        // Effective permissions are cached per user; without this the change would not show
        // up until the cache expired.
        $this->cache->clearAllCache();
    }

    /**
     * Put a user in a group, or take them out.
     *
     * Stated as the state you want rather than as a toggle, so a double-click or a retried
     * request lands on the same answer instead of undoing itself.
     *
     * @throws LastAdministratorException
     */
    public function setMembership(Group $group, Model $user, bool $member): void
    {
        // The one membership change that can lock everybody out, including the person
        // making it. Here rather than in a UI, because a UI is not the only way in.
        if (! $member && $this->isProtected($group) && $group->users()->count() <= 1) {
            throw new LastAdministratorException(
                "This is the last member of {$group->name}. Add another before removing this one."
            );
        }

        $member ? $user->joinGroup($group) : $user->leaveGroup($group);

        // Only this user's. Clearing everybody's would mean rebuilding every signed-in
        // user's permissions for a change that affected one person.
        $user->clearPermissionCache();
    }

    /**
     * Current permissions as group id => resource identifier => letters.
     *
     * @param Collection<int, Group> $groups
     * @return array<int, array<string, string>>
     */
    public function matrixFor(Collection $groups): array
    {
        $permissions = Permission::with('systemResource')
            ->whereIn('permissionable_id', $groups->pluck('id'))
            ->where('permissionable_type', (new Group())->getMorphClass())
            ->get();

        $matrix = [];

        foreach ($groups as $group) {
            $matrix[$group->id] = [];
        }

        foreach ($permissions as $permission) {
            if (! $permission->systemResource) {
                continue;
            }

            $letters = '';

            foreach (PermissionMap::ACTIONS as $column => $letter) {
                if ($permission->$column) {
                    $letters .= $letter;
                }
            }

            $matrix[$permission->permissionable_id][$permission->systemResource->identifier] = $letters;
        }

        return $matrix;
    }

    /**
     * Expand a letter string into the action names `Permission::createFor` expects.
     *
     * @return array<int, string>
     */
    public function actionsFromLetters(string $letters): array
    {
        $names = array_flip(PermissionMap::ACTIONS);
        $actions = [];

        foreach (str_split($letters) as $letter) {
            if (isset($names[$letter])) {
                // 'can_create' -> 'create'
                $actions[] = substr($names[$letter], 4);
            }
        }

        return array_values(array_unique($actions));
    }
}
